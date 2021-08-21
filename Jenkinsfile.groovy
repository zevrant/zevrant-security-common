pipeline {
    agent {
        label 'master'
    }
    stages {
        stage('Launch Build') {
            steps {
                script {
                    build(
                            job: 'Libraries/Zevrant Security Common/zevrant-security-common',
                            propagate: true,
                            wait: true,
                            parameters: [
                                    [$class: 'StringParameterValue', name: 'BRANCHNAME', value: env.BRANCH_NAME],
                            ]
                    )
                }
            }
        }
    }
}
