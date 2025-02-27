document.addEventListener('DOMContentLoaded', function() {
    // 注册表单提交事件
    const registerForm = document.getElementById('registerForm');
    if (registerForm) {
        registerForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const formData = new FormData(this);
            fetch('/register', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    alert(data.message);  // 显示注册成功消息
                    window.location.href = '/login_page';  // 跳转到登录页面
                } else {
                    alert(data.message);  // 显示错误消息
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('注册过程中发生错误，请稍后重试。');
            });
        });
    } else {
        console.error('registerForm not found');
    }

    // 登录表单提交事件
    const loginForm = document.getElementById('authForm');
    if (loginForm) {
        loginForm.addEventListener('submit', function(event) {
            event.preventDefault();
            const formData = new FormData(this);
            fetch('/login', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.status === 'success') {
                    alert(data.message);  // 显示登录成功消息
                    window.location.href = '/';  // 跳转到首页
                } else {
                    alert(data.message);  // 显示错误消息
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('登录过程中发生错误，请稍后重试。');
            });
        });
    } else {
        console.error('authForm not found');
    }
});