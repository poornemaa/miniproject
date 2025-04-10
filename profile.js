const token = localStorage.getItem('token');
const userId = localStorage.getItem('user_id');

if (!token) {
  alert('Please login first.');
  window.location.href = '/';
}

// Load user profile
document.addEventListener('DOMContentLoaded', async () => {
  try {
    const res = await fetch(`/api/users/${userId}`, {
      headers: {
        'Authorization': 'Bearer ' + token
      }
    });
    const user = await res.json();
    document.getElementById('username').value = user.username;
    document.getElementById('email').value = user.email;
  } catch (err) {
    console.error('Error loading profile:', err);
  }
});

// Update user profile
document.getElementById('profileForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const username = document.getElementById('username').value;

  try {
    const res = await fetch(`/api/users/${userId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + token
      },
      body: JSON.stringify({ username })
    });
    const data = await res.json();
    document.getElementById('message').innerHTML = `<div class="alert alert-success">${data.message || data.error}</div>`;

    if (res.ok) {
      localStorage.setItem('username', username); // Update local storage too
    }
  } catch (err) {
    console.error('Error updating profile:', err);
  }
});
