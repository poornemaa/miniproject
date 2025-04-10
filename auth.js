// Forgot Password
if (document.getElementById('forgotPasswordForm')) {
    document.getElementById('forgotPasswordForm').addEventListener('submit', async function (e) {
      e.preventDefault();
  
      const email = document.getElementById('email').value;
  
      try {
        const response = await fetch('/api/auth/forgot-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email })
        });
  
        const data = await response.json();
        document.getElementById('message').innerHTML = response.ok 
          ? `<div class="alert alert-success">${data.message}</div>`
          : `<div class="alert alert-danger">${data.error}</div>`;
  
      } catch (error) {
        console.error('Error:', error);
      }
    });
  }
  
  // Reset Password
  if (document.getElementById('resetPasswordForm')) {
    document.getElementById('resetPasswordForm').addEventListener('submit', async function (e) {
      e.preventDefault();
  
      const urlParams = new URLSearchParams(window.location.search);
      const token = urlParams.get('token');
      const newPassword = document.getElementById('newPassword').value;
  
      try {
        const response = await fetch('/api/auth/reset-password', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token, newPassword })
        });
  
        const data = await response.json();
        document.getElementById('message').innerHTML = response.ok
          ? `<div class="alert alert-success">${data.message}</div>`
          : `<div class="alert alert-danger">${data.error}</div>`;
  
        if (response.ok) {
          setTimeout(() => {
            window.location.href = '/';
          }, 2000);
        }
  
      } catch (error) {
        console.error('Error:', error);
      }
    });
  }
  