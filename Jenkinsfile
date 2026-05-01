pipeline {

    agent any

    environment {
        APP_NAME        = "trivy-poc-app"
        IMAGE_NAME      = "trivy-poc-app:${BUILD_NUMBER}"
        IMAGE_LATEST    = "trivy-poc-app:latest"
        TRIVY_CACHE_DIR = "${WORKSPACE}/.trivy-cache"
        TRIVY_SEVERITY  = "CRITICAL,HIGH,MEDIUM"
        REPORT_DIR      = "${WORKSPACE}/trivy-reports"
        REPO_REPORT     = "${REPORT_DIR}/01-repo-scan.json"
        FS_REPORT       = "${REPORT_DIR}/02-fs-scan.json"
        IMAGE_REPORT    = "${REPORT_DIR}/03-image-scan.json"
        HTML_REPORT     = "${REPORT_DIR}/trivy-final-report.html"
        EMAIL_TO        = "YOUR_EMAIL@gmail.com"
    }

    options {
        buildDiscarder(logRotator(numToKeepStr: '5'))
        timeout(time: 30, unit: 'MINUTES')
        timestamps()
    }

    stages {

        // ════════════════════════════════
        // STAGE 1: Install Trivy + Setup
        // ════════════════════════════════
        stage('Setup: Trivy Install') {
            steps {
                sh '''
                    mkdir -p ${REPORT_DIR}
                    mkdir -p ${TRIVY_CACHE_DIR}

                    if ! command -v trivy &> /dev/null; then
                        echo "Installing Trivy..."
                        sudo apt-get install -y wget gnupg apt-transport-https
                        wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
                        echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/trivy.list
                        sudo apt-get update -y
                        sudo apt-get install -y trivy
                    fi

                    echo "✅ Trivy version: $(trivy --version)"

                    echo "Downloading vulnerability DB..."
                    trivy image --download-db-only --cache-dir ${TRIVY_CACHE_DIR}
                    echo "✅ DB ready"
                '''
            }
        }

        // ════════════════════════════════
        // STAGE 2: Checkout Code
        // ════════════════════════════════
        stage('Checkout: Git Pull') {
            steps {
                checkout scm
                sh '''
                    echo "✅ Code checked out"
                    echo "Commit: $(git log --oneline -1)"
                    ls -la
                '''
            }
        }

        // ════════════════════════════════
        // STAGE 3: Trivy Repo Scan
        // Finds: secrets, IaC misconfigs,
        //        vulnerable dependencies
        // ════════════════════════════════
        stage('Trivy: Repo Scan') {
            steps {
                sh '''
                    echo "=========================================="
                    echo " TRIVY REPO SCAN"
                    echo " Scanning for: secrets, misconfigs, vulns"
                    echo "=========================================="

                    trivy repo \
                        --cache-dir ${TRIVY_CACHE_DIR} \
                        --scanners  secret,misconfig,vuln \
                        --format    json \
                        --output    ${REPO_REPORT} \
                        --exit-code 0 \
                        . || true

                    echo ""
                    echo "--- REPO SCAN CONSOLE SUMMARY ---"
                    trivy repo \
                        --cache-dir ${TRIVY_CACHE_DIR} \
                        --scanners  secret,misconfig,vuln \
                        --format    table \
                        --severity  ${TRIVY_SEVERITY} \
                        --exit-code 0 \
                        . || true

                    echo "✅ Repo scan done → ${REPO_REPORT}"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-reports/01-repo-scan.json',
                                     allowEmptyArchive: true
                }
            }
        }

        // ════════════════════════════════
        // STAGE 4: Trivy Filesystem Scan
        // Finds: all files, Dockerfile
        //        misconfigs, secrets
        // ════════════════════════════════
        stage('Trivy: Filesystem Scan') {
            steps {
                sh '''
                    echo "=========================================="
                    echo " TRIVY FILESYSTEM SCAN"
                    echo " Scanning all files in workspace"
                    echo "=========================================="

                    trivy fs \
                        --cache-dir ${TRIVY_CACHE_DIR} \
                        --scanners  vuln,secret,misconfig \
                        --format    json \
                        --output    ${FS_REPORT} \
                        --exit-code 0 \
                        . || true

                    echo ""
                    echo "--- FILESYSTEM SCAN CONSOLE SUMMARY ---"
                    trivy fs \
                        --cache-dir ${TRIVY_CACHE_DIR} \
                        --scanners  vuln,secret,misconfig \
                        --format    table \
                        --severity  ${TRIVY_SEVERITY} \
                        --exit-code 0 \
                        . || true

                    echo "✅ Filesystem scan done → ${FS_REPORT}"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-reports/02-fs-scan.json',
                                     allowEmptyArchive: true
                }
            }
        }

        // ════════════════════════════════
        // STAGE 5: Build Docker Image
        // ════════════════════════════════
        stage('Docker: Build Image') {
            steps {
                sh '''
                    echo "=========================================="
                    echo " DOCKER BUILD"
                    echo " Building: ${IMAGE_NAME}"
                    echo "=========================================="

                    docker build \
                        -t ${IMAGE_NAME} \
                        -t ${IMAGE_LATEST} \
                        .

                    echo "✅ Image built: ${IMAGE_NAME}"
                    docker images | grep trivy-poc-app
                '''
            }
        }

        // ════════════════════════════════
        // STAGE 6: Trivy Image Scan
        // Finds: OS CVEs, app package
        //        CVEs, image secrets
        // ════════════════════════════════
        stage('Trivy: Image Scan') {
            steps {
                sh '''
                    echo "=========================================="
                    echo " TRIVY IMAGE SCAN"
                    echo " Scanning: ${IMAGE_NAME}"
                    echo "=========================================="

                    trivy image \
                        --cache-dir ${TRIVY_CACHE_DIR} \
                        --scanners  vuln,secret,misconfig \
                        --format    json \
                        --output    ${IMAGE_REPORT} \
                        --severity  ${TRIVY_SEVERITY} \
                        --exit-code 0 \
                        ${IMAGE_NAME} || true

                    echo ""
                    echo "--- IMAGE SCAN CONSOLE SUMMARY ---"
                    trivy image \
                        --cache-dir ${TRIVY_CACHE_DIR} \
                        --scanners  vuln,secret,misconfig \
                        --format    table \
                        --severity  ${TRIVY_SEVERITY} \
                        --exit-code 0 \
                        ${IMAGE_NAME} || true

                    echo "✅ Image scan done → ${IMAGE_REPORT}"
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'trivy-reports/03-image-scan.json',
                                     allowEmptyArchive: true
                }
            }
        }

        // ════════════════════════════════
        // STAGE 7: Generate HTML Report
        // Merges all 3 scan JSONs into
        // one beautiful HTML report
        // ════════════════════════════════
        stage('Report: Generate HTML') {
            steps {
                sh '''
                    echo "=========================================="
                    echo " GENERATING ENHANCED HTML REPORT"
                    echo "=========================================="

                    python3 ${WORKSPACE}/generate-report.py \
                        --repo-report   ${REPO_REPORT} \
                        --fs-report     ${FS_REPORT} \
                        --image-report  ${IMAGE_REPORT} \
                        --output        ${HTML_REPORT} \
                        --app-name      "${APP_NAME}" \
                        --build-number  "${BUILD_NUMBER}" \
                        --image-name    "${IMAGE_NAME}"

                    echo "✅ HTML Report generated: ${HTML_REPORT}"
                    ls -lh ${REPORT_DIR}/
                '''

                publishHTML([
                    allowMissing:          true,
                    alwaysLinkToLastBuild: true,
                    keepAll:               true,
                    reportDir:             'trivy-reports',
                    reportFiles:           'trivy-final-report.html',
                    reportName:            'Trivy Security Report'
                ])
            }
        }

        // ════════════════════════════════
        // STAGE 8: Send Email Report
        // ════════════════════════════════
        stage('Notify: Email Report') {
            steps {
                script {
                    def htmlContent = readFile("${env.HTML_REPORT}")

                    emailext(
                        subject: "[Trivy] ${env.APP_NAME} Build #${env.BUILD_NUMBER} — ${currentBuild.currentResult}",
                        body: htmlContent,
                        mimeType: 'text/html',
                        to: "${env.EMAIL_TO}",
                        attachmentsPattern: 'trivy-reports/*.json'
                    )

                    echo "✅ Email sent to ${env.EMAIL_TO}"
                }
            }
        }

    } // end stages

    post {
        always {
            echo "=== Build ${currentBuild.currentResult} ==="
            archiveArtifacts artifacts: 'trivy-reports/**/*',
                             allowEmptyArchive: true
            sh '''
                docker rmi ${IMAGE_NAME} ${IMAGE_LATEST} || true
                docker image prune -f || true
            '''
        }
        success {
            echo "✅ Pipeline PASSED — All scans complete!"
        }
        failure {
            echo "❌ Pipeline FAILED — Check logs above!"
            emailext(
                subject: "[ALERT] Trivy Pipeline FAILED — ${env.APP_NAME} #${env.BUILD_NUMBER}",
                body: """<h2 style='color:red'>Pipeline Failed!</h2>
                         <p>Build #${env.BUILD_NUMBER} failed.</p>
                         <p>Check Jenkins: ${env.BUILD_URL}</p>""",
                mimeType: 'text/html',
                to: "${env.EMAIL_TO}"
            )
        }
    }

} // end pipeline
