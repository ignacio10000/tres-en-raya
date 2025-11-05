class Auth {
    constructor() {
        this.clientId = 'ignacio10000'; // Reemplaza con tu Client ID de GitHub
        this.redirectUri = window.location.origin + '/auth/callback.html';
        this.loginBtn = document.getElementById('login-btn');
        this.logoutBtn = document.getElementById('logout-btn');
        this.userProfile = document.getElementById('user-profile');
        this.userAvatar = document.getElementById('user-avatar');
        this.username = document.getElementById('username');
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.checkAuth();
    }

    setupEventListeners() {
        if (this.loginBtn) {
            this.loginBtn.addEventListener('click', () => this.redirectToGitHub());
        }
        
        if (this.logoutBtn) {
            this.logoutBtn.addEventListener('click', () => this.logout());
        }
    }

    redirectToGitHub() {
        const authUrl = `https://github.com/login/oauth/authorize?client_id=${this.clientId}&redirect_uri=${encodeURIComponent(this.redirectUri)}&scope=user:email`;
        window.location.href = authUrl;
    }

    async checkAuth() {
        const code = localStorage.getItem('github_auth_code');
        
        if (code) {
            try {
                const token = await this.getAccessToken(code);
                if (token) {
                    const userData = await this.fetchUserData(token);
                    this.showUserProfile(userData);
                    // Limpiar el código después de usarlo
                    localStorage.removeItem('github_auth_code');
                }
            } catch (error) {
                console.error('Error en la autenticación:', error);
                this.logout();
            }
        }
    }

    async getAccessToken(code) {
        try {
            // En un entorno de producción, esto debería hacerse en el backend
            // Para desarrollo local, puedes usar un proxy o un servicio como ngrok
            const response = await fetch('https://tres-en-raya-auth.vercel.app/api/auth', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    code,
                    client_id: this.clientId,
                    redirect_uri: this.redirectUri
                })
            });
            
            const data = await response.json();
            if (data.token) {
                localStorage.setItem('github_token', data.token);
                return data.token;
            }
            throw new Error('No se pudo obtener el token de acceso');
        } catch (error) {
            console.error('Error al obtener token:', error);
            throw error;
        }
    }

    async fetchUserData(token) {
        const response = await fetch('https://api.github.com/user', {
            headers: {
                'Authorization': `token ${token}`
            }
        });
        
        if (!response.ok) {
            throw new Error('Error al obtener datos del usuario');
        }
        
        return await response.json();
    }

    showUserProfile(userData) {
        if (!this.userProfile || !this.userAvatar || !this.username) return;
        
        this.userAvatar.src = userData.avatar_url || '';
        this.username.textContent = userData.name || userData.login || 'Usuario';
        this.userProfile.classList.remove('hidden');
        if (this.loginBtn) this.loginBtn.classList.add('hidden');
        
        // Aquí puedes guardar la información del usuario si lo necesitas
        localStorage.setItem('user_data', JSON.stringify(userData));
    }

    logout() {
        localStorage.removeItem('github_token');
        localStorage.removeItem('user_data');
        localStorage.removeItem('github_auth_code');
        
        if (this.userProfile) this.userProfile.classList.add('hidden');
        if (this.loginBtn) this.loginBtn.classList.remove('hidden');
        
        // Recargar la página para limpiar el estado
        window.location.href = '/';
    }
}

// Inicializar autenticación cuando el DOM esté listo
document.addEventListener('DOMContentLoaded', () => {
    window.auth = new Auth();
});
