// ================================================================
// TRIVY POC - COMPLETE JENKINS PIPELINE
// Covers: Repo Scan → FS Scan → Build → Image Scan →
//         Push ECR → Deploy ECS/EKS → AWS Scan → Report → Email
// ================================================================

pipeline {

    agent any

    // ─────────────────────────────────────────────────────────
    // ENVIRONMENT VARIABLES
    // ─────────────────────────────────────────────────────────
    environment {
        // App Config
        APP_NAME        = "trivy-poc-app"
        APP_VERSION     = "${BUILD_NUMBER}"

        // Docker
        IMAGE_NAME      = "${APP_NAME}:${BUILD_NUMBER}"
        IMAGE_LATEST    = "${APP_NAME}:latest"

        // AWS Config — use Jenkins Credentials (never hardcode!)
        AWS_REGION      = "ap-south-1"
        ECR_REGISTRY    = "123456789012.dkr.ecr.ap-south-1.amazonaws.com"
        ECR_REPO        = "${ECR_REGISTRY}/${APP_NAME}"

        // ECS Config
        ECS_CLUSTER     = "my-cluster"
        ECS_SERVICE     = "my-service"

        // EKS Config (if using EKS instead of ECS)
        EKS_CLUSTER     = "my-eks-cluster"

        // Trivy Config
        TRIVY_VERSION   = "0.50.1"
        TRIVY_CACHE_DIR = "${WORKSPACE}/.trivy-cache"
        TRIVY_SEVERITY  = "CRITICAL,HIGH"  // what to flag
        TRIVY_EXIT_CODE = "1"              // 1 = fail pipeline on vuln found

        // Report paths
        REPORT_DIR      = "${WORKSPACE}/trivy-reports"
        REPO_REPORT     = "${REPORT_DIR}/01-repo-scan.json"
        FS_REPORT       = "${REPORT_DIR}/02-fs-scan.json"
        IMAGE_REPORT    = "${REPORT_DIR}/03-image-scan.json"
        AWS_REPORT      = "${REPORT_DIR}/04-aws-scan.json"
        HTML_REPORT     = "${REPORT_DIR}/trivy-final-report.html"
    }

    // ─────────────────────────────────────────────────────────
    // PIPELINE OPTIONS
    // ─────────────────────────────────────────────────────────
    options {
        // Keep last 10 builds
        buildDiscarder(logRotator(numToKeepStr: '10'))
        // Timeout entire pipeline after 60 mins
        timeout(time: 60, unit: 'MINUTES')
        // Add timestamps to console log
        timestamps()
    }

    // ─────────────────────────────────────────────────────────
    // PARAMETERS (can be changed per build in Jenkins UI)
    // ─────────────────────────────────────────────────────────
    parameters {
        choice(
            name: 'DEPLOY_TARGET',
            choices: ['ECS', 'EKS', 'NONE'],
            description: 'Where to deploy after build'
        )
        booleanParam(
            name: 'SKIP_AWS_SCAN',
            defaultValue: false,
            description: 'Skip AWS cloud scan (needs AWS credentials)'
        )
        booleanParam(
            name: 'FAIL_ON_VULN',
            defaultValue: false,
            description: 'Fail pipeline if CRITICAL/HIGH vulns found'
        )
    }

    // ─────────────────────────────────────────────────────────
    // STAGES
    // ─────────────────────────────────────────────────────────
    stages {

        // ══════════════════════════════════════════════════
        // STAGE 1: Setup — Install Trivy + Create Report Dir
        // ══════════════════════════════════════════════════
        stage('Setup: Install Trivy') {
            steps {
                echo "=== Setting up Trivy ==="

                sh '''
                    # Create reports directory
                    mkdir -p ${REPORT_DIR}
                    mkdir -p ${TRIVY_CACHE_DIR}

                    # Check if trivy already installed
                    if ! command -v trivy &> /dev/null; then
                        echo "Installing Trivy ${TRIVY_VERSION}..."
                        
                        # Install on Ubuntu/Debian
                        sudo apt-get install -y wget apt-transport-https gnupg lsb-release
                        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
                        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
                        sudo apt-get update
                        sudo apt-get install -y trivy

                        # OR via script (alternative):
                        # curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin v${TRIVY_VERSION}
                    else
                        echo "Trivy already installed: $(trivy --version)"
                    fi

                    # Download/Update vulnerability DB
                    # Cache dir avoids re-downloading on every run
                    trivy image --download-db-only --cache-dir ${TRIVY_CACHE_DIR}

                    echo "Trivy setup complete!"
                    trivy --version
                '''
            }
        }

        // ══════════════════════════════════════════════════
        // STAGE 2: Checkout Code from GitHub
        // ══════════════════════════════════════════════════
        stage('Checkout: Git Pull') {
            steps {
                echo "=== Checking out source code ==="

                // Jenkins SCM checkout (configured in job config)
                checkout scm

                // Show what was checked out
                sh '''
                    echo "Branch: $(git branch --show-current)"
                    echo "Commit: $(git log --oneline -1)"
                    echo "Files:"
                    ls -la
                '''
            }
        }

        // ══════════════════════════════════════════════════
        // STAGE 3: Trivy — Git Repository Scan
        // Scans: secrets in code, vulnerable deps, IaC issues
        // ══════════════════════════════════════════════════
        stage('Trivy: Repo Scan') {
            steps {
                echo "=== Trivy Repository Scan ==="

                sh '''
                    echo "Scanning git repository for secrets, IaC misconfigs, and vulnerable dependencies..."

                    trivy repo \
                        --cache-dir ${TRIVY_CACHE_DIR} \
                        --scanners secret,misconfig,vuln \
                        --format json \
                        --output ${REPO_REPORT} \
                        --severity ${TRIVY_SEVERITY} \
                        --exit-code 0 \
                        .

                    # Also print table format to Jenkins console for visibility
                    echo ""
                    echo "=== REPO SCAN SUMMARY (Console) ==="
                    trivy repo \
                        --cache-dir ${TRIVY_CACHE_DIR} \
                        --scanners secret,misconfig,vuln \
                        --format table \
                        --severity ${TRIVY_SEVERITY} \
                        --exit-code 0 \
                        . || true

                    echo "Repo scan complete. Report saved: ${REPO_REPORT}"
                '''
            }
            post {
                always {
                    // Archive repo scan JSON report as Jenkins artifact
                    archiveArtifacts artifacts: 'trivy-reports/01-repo-scan.json',
                                     allowEmptyArchive: true
                }
            }
        }

        // ══════════════════════════════════════════════════
        // STAGE 4: Trivy — Filesystem Scan
        // Scans: all files in workspace deeply
        // ══════════════════════════════════════════════════
        stage('Trivy: Filesystem Scan') {
            steps {
                echo "=== Trivy Filesystem Scan ==="

                sh '''
                    echo "Scanning filesystem for vulnerabilities, secrets, and misconfigs..."

                    trivy fs \
                        --cache-dir ${TRIVY_CACHE_DIR} \
                        --scanners vuln,secret,misconfig \
                        --format json \
                        --output ${FS_REPORT} \
                        --severity ${TRIVY_SEVERITY} \
                        --exit-code 0 \
                        .

                    # Console summary
                    echo ""
                    echo "=== FILESYSTEM SCAN SUMMARY (Console) ==="
                    trivy fs \
                        --cache-dir ${TRIVY_CACHE_DIR} \
                        --scanners vuln,secret,misconfig \
                        --format table \
                        --severity ${TRIVY_SEVERITY} \
                        --exit-code 0 \
                        . || true

                    echo "Filesystem scan complete. Report: ${FS_REPORT}"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-reports/02-fs-scan.json',
                                     allowEmptyArchive: true
                }
            }
        }

        // ══════════════════════════════════════════════════
        // STAGE 5: Build Docker Image
        // ══════════════════════════════════════════════════
        stage('Docker: Build Image') {
            steps {
                echo "=== Building Docker Image ==="

                sh '''
                    echo "Building image: ${IMAGE_NAME}"

                    docker build \
                        -t ${IMAGE_NAME} \
                        -t ${IMAGE_LATEST} \
                        --label "build.number=${BUILD_NUMBER}" \
                        --label "git.commit=$(git rev-parse --short HEAD)" \
                        --label "build.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
                        .

                    echo "Image built successfully!"
                    docker images | grep ${APP_NAME}
                '''
            }
        }

        // ══════════════════════════════════════════════════
        // STAGE 6: Trivy — Docker Image Scan
        // Scans: OS packages, app libraries, image secrets
        // This is the GATE — fails pipeline if CRITICAL found
        // ══════════════════════════════════════════════════
        stage('Trivy: Image Scan') {
            steps {
                echo "=== Trivy Docker Image Scan ==="

                script {
                    // Determine exit code based on parameter
                    def exitCode = params.FAIL_ON_VULN ? "1" : "0"

                    sh """
                        echo "Scanning Docker image: ${IMAGE_NAME}"
                        echo "Severity filter: ${TRIVY_SEVERITY}"
                        echo "Fail on vuln: ${params.FAIL_ON_VULN}"

                        # Full scan — save JSON report
                        trivy image \\
                            --cache-dir ${TRIVY_CACHE_DIR} \\
                            --scanners vuln,secret,misconfig \\
                            --format json \\
                            --output ${IMAGE_REPORT} \\
                            --severity ${TRIVY_SEVERITY} \\
                            --exit-code 0 \\
                            ${IMAGE_NAME}

                        # Console summary with exit code gate
                        echo ""
                        echo "=== IMAGE SCAN SUMMARY (Console) ==="
                        trivy image \\
                            --cache-dir ${TRIVY_CACHE_DIR} \\
                            --scanners vuln,secret,misconfig \\
                            --format table \\
                            --severity ${TRIVY_SEVERITY} \\
                            --exit-code ${exitCode} \\
                            ${IMAGE_NAME}

                        echo "Image scan complete. Report: ${IMAGE_REPORT}"
                    """
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-reports/03-image-scan.json',
                                     allowEmptyArchive: true
                }
                failure {
                    echo "IMAGE SCAN FAILED — CRITICAL/HIGH vulnerabilities found!"
                    echo "Pipeline blocked. Fix vulnerabilities before deploying."
                }
            }
        }

        // ══════════════════════════════════════════════════
        // STAGE 7: Push Docker Image to AWS ECR
        // ══════════════════════════════════════════════════
        stage('ECR: Push Image') {
            steps {
                echo "=== Pushing to AWS ECR ==="

                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: 'aws-credentials',
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
                    sh '''
                        echo "Logging into ECR..."
                        aws ecr get-login-password --region ${AWS_REGION} | \
                            docker login --username AWS --password-stdin ${ECR_REGISTRY}

                        echo "Tagging image for ECR..."
                        docker tag ${IMAGE_NAME} ${ECR_REPO}:${BUILD_NUMBER}
                        docker tag ${IMAGE_NAME} ${ECR_REPO}:latest

                        echo "Pushing to ECR..."
                        docker push ${ECR_REPO}:${BUILD_NUMBER}
                        docker push ${ECR_REPO}:latest

                        echo "Push complete!"
                        echo "Image URI: ${ECR_REPO}:${BUILD_NUMBER}"
                    '''
                }
            }
        }

        // ══════════════════════════════════════════════════
        // STAGE 8: Deploy to ECS or EKS (based on parameter)
        // ══════════════════════════════════════════════════
        stage('Deploy: ECS or EKS') {
            steps {
                echo "=== Deploying Application ==="

                script {
                    if (params.DEPLOY_TARGET == 'ECS') {
                        deployToECS()
                    } else if (params.DEPLOY_TARGET == 'EKS') {
                        deployToEKS()
                    } else {
                        echo "DEPLOY_TARGET=NONE — Skipping deployment"
                    }
                }
            }
        }

        // ══════════════════════════════════════════════════
        // STAGE 9: Trivy — AWS Cloud Scan
        // Scans: ECR, ECS, EKS, S3, IAM, Security Groups
        // ══════════════════════════════════════════════════
        stage('Trivy: AWS Cloud Scan') {
            when {
                expression { return !params.SKIP_AWS_SCAN }
            }
            steps {
                echo "=== Trivy AWS Cloud Scan ==="

                withCredentials([[
                    $class: 'AmazonWebServicesCredentialsBinding',
                    credentialsId: 'aws-credentials',
                    accessKeyVariable: 'AWS_ACCESS_KEY_ID',
                    secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
                ]]) {
                    sh '''
                        echo "Scanning AWS cloud configuration..."
                        echo "Region: ${AWS_REGION}"

                        trivy aws \
                            --cache-dir ${TRIVY_CACHE_DIR} \
                            --region ${AWS_REGION} \
                            --format json \
                            --output ${AWS_REPORT} \
                            --severity ${TRIVY_SEVERITY} \
                            --exit-code 0 \
                            --service ecr \
                            --service ecs \
                            --service eks \
                            --service s3 \
                            --service iam \
                            --service ec2

                        # Console summary
                        echo ""
                        echo "=== AWS SCAN SUMMARY (Console) ==="
                        trivy aws \
                            --cache-dir ${TRIVY_CACHE_DIR} \
                            --region ${AWS_REGION} \
                            --format table \
                            --severity ${TRIVY_SEVERITY} \
                            --exit-code 0 \
                            --service ecr \
                            --service ecs \
                            --service s3 \
                            --service iam \
                            --service ec2 || true

                        echo "AWS scan complete. Report: ${AWS_REPORT}"
                    '''
                }
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-reports/04-aws-scan.json',
                                     allowEmptyArchive: true
                }
            }
        }

        // ══════════════════════════════════════════════════
        // STAGE 10: Generate Enhanced HTML Report
        // Merges all 4 scan reports into one beautiful HTML
        // ══════════════════════════════════════════════════
        stage('Report: Generate HTML') {
            steps {
                echo "=== Generating Enhanced HTML Report ==="

                sh '''
                    echo "Merging all scan results into HTML report..."

                    python3 ${WORKSPACE}/generate-report.py \
                        --repo-report   ${REPO_REPORT} \
                        --fs-report     ${FS_REPORT} \
                        --image-report  ${IMAGE_REPORT} \
                        --aws-report    ${AWS_REPORT} \
                        --output        ${HTML_REPORT} \
                        --app-name      "${APP_NAME}" \
                        --build-number  "${BUILD_NUMBER}" \
                        --image-name    "${IMAGE_NAME}"

                    echo "HTML report generated: ${HTML_REPORT}"
                '''

                // Publish HTML report in Jenkins UI
                publishHTML([
                    allowMissing:          false,
                    alwaysLinkToLastBuild: true,
                    keepAll:               true,
                    reportDir:             'trivy-reports',
                    reportFiles:           'trivy-final-report.html',
                    reportName:            'Trivy Security Report',
                    reportTitles:          'Trivy Security Report'
                ])
            }
        }

        // ══════════════════════════════════════════════════
        // STAGE 11: Send Email with HTML Report
        // ══════════════════════════════════════════════════
        stage('Notify: Send Email') {
            steps {
                echo "=== Sending Email Report ==="

                script {
                    // Read the generated HTML report
                    def htmlReport = readFile("${REPORT_DIR}/trivy-final-report.html")

                    emailext(
                        subject: "[Trivy Scan] ${APP_NAME} Build #${BUILD_NUMBER} — ${currentBuild.currentResult}",
                        body: htmlReport,
                        mimeType: 'text/html',
                        to: 's.harisankar21122002@gmail.com.com,security-team@yourcompany.com',
                        replyTo: 'jenkins@yourcompany.com',
                        attachmentsPattern: 'trivy-reports/*.json',
                        attachLog: false
                    )

                    echo "Email sent to team!"
                }
            }
        }

    } // end stages

    // ─────────────────────────────────────────────────────────
    // POST BUILD ACTIONS
    // ─────────────────────────────────────────────────────────
    post {

        always {
            echo "=== Pipeline Complete: ${currentBuild.currentResult} ==="

            // Archive all reports
            archiveArtifacts artifacts: 'trivy-reports/**/*',
                             allowEmptyArchive: true

            // Clean up Docker images to save disk space
            sh '''
                docker rmi ${IMAGE_NAME} ${IMAGE_LATEST} || true
                docker image prune -f || true
            '''
        }

        success {
            echo "PIPELINE PASSED — Image is clean and deployed!"
        }

        failure {
            echo "PIPELINE FAILED — Check Trivy reports for issues!"

            // Send failure email
            emailext(
                subject: "[ALERT] Trivy Scan FAILED — ${APP_NAME} Build #${BUILD_NUMBER}",
                body: """
                    <h2 style="color:red;">Pipeline Failed!</h2>
                    <p>Build: ${BUILD_NUMBER}</p>
                    <p>App: ${APP_NAME}</p>
                    <p>Reason: Critical vulnerabilities found or build error</p>
                    <p>Check Jenkins: ${BUILD_URL}</p>
                    <p>Check Trivy Reports in build artifacts.</p>
                """,
                mimeType: 'text/html',
                to: 'devops-team@yourcompany.com'
            )
        }
    }

} // end pipeline


// ================================================================
// HELPER FUNCTIONS
// ================================================================

def deployToECS() {
    withCredentials([[
        $class: 'AmazonWebServicesCredentialsBinding',
        credentialsId: 'aws-credentials',
        accessKeyVariable: 'AWS_ACCESS_KEY_ID',
        secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
    ]]) {
        sh """
            echo "Deploying to ECS..."
            echo "Cluster: ${ECS_CLUSTER}"
            echo "Service: ${ECS_SERVICE}"

            # Force new deployment with the new image
            aws ecs update-service \\
                --cluster ${ECS_CLUSTER} \\
                --service ${ECS_SERVICE} \\
                --force-new-deployment \\
                --region ${AWS_REGION}

            # Wait for deployment to stabilize
            echo "Waiting for ECS deployment to stabilize..."
            aws ecs wait services-stable \\
                --cluster ${ECS_CLUSTER} \\
                --services ${ECS_SERVICE} \\
                --region ${AWS_REGION}

            echo "ECS deployment complete!"
        """
    }
}

def deployToEKS() {
    withCredentials([[
        $class: 'AmazonWebServicesCredentialsBinding',
        credentialsId: 'aws-credentials',
        accessKeyVariable: 'AWS_ACCESS_KEY_ID',
        secretKeyVariable: 'AWS_SECRET_ACCESS_KEY'
    ]]) {
        sh """
            echo "Deploying to EKS..."

            # Update kubeconfig for EKS
            aws eks update-kubeconfig \\
                --region ${AWS_REGION} \\
                --name ${EKS_CLUSTER}

            # Update image in deployment
            kubectl set image deployment/${APP_NAME} \\
                ${APP_NAME}=${ECR_REPO}:${BUILD_NUMBER} \\
                --namespace default

            # Wait for rollout
            kubectl rollout status deployment/${APP_NAME} \\
                --namespace default \\
                --timeout=5m

            echo "EKS deployment complete!"
        """
    }
}
