module.exports = {
    uiPort: 1880,
    credentialSecret: false,
    adminAuth: {
        type: "credentials",
        users: [{
            username: "admin",
            password: "$2b$08$yRDhYwpIaL7oualUiQCwreUkwrs3XxMKRQYvU2.G0cSGcNCEuDiPC",
            permissions: "*"
        }]
    },
    logging: {
        console: { level: "info", metrics: false, audit: false }
    },
    editorTheme: {
        projects: { enabled: false }
    }
}
