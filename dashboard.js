const username = localStorage.getItem('username');
const userType = localStorage.getItem('user_type');
const userId = localStorage.getItem('user_id');
const token = localStorage.getItem('token');

if (!token) {
  alert('You must be logged in!');
  window.location.href = '/';
}

// Update Welcome Text
document.getElementById('welcomeText').innerText = `Welcome, ${username}! You are logged in as ${userType}.`;

// Hide "Add Donation" and "Certification" button if recipient
if (userType.toLowerCase() !== 'donor') {
  document.getElementById('addDonationBtn').style.display = 'none';
  document.getElementById('certificationsBtn').style.display = 'none';
}

// Logout Button
document.getElementById('logoutBtn').addEventListener('click', () => {
  localStorage.clear();
  window.location.href = '/';
});
