# Jenkins Integration

Add to your `Jenkinsfile`:

```groovy
pipeline {
    agent any

    stages {
        stage('Security Scan') {
            steps {
                sh 'curl -fsSL https://install.armur.ai | sh'
                sh 'armur scan . --fail-on-severity high --format sarif --output results.sarif'
            }
            post {
                always {
                    archiveArtifacts artifacts: 'results.sarif', allowEmptyArchive: true
                }
            }
        }
    }
}
```
