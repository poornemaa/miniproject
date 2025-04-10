// Load certifications if on certifications page
document.addEventListener('DOMContentLoaded', loadCertifications);

async function loadCertifications() {
  const token = localStorage.getItem('token');
  const userId = localStorage.getItem('user_id');

  if (!token) {
    alert('You must be logged in!');
    window.location.href = '/';
    return;
  }

  try {
    const response = await fetch('/api/certifications', {
      headers: {
        'Authorization': 'Bearer ' + token
      }
    });

    const certifications = await response.json();
    const table = document.getElementById('certificationsTable');
    table.innerHTML = '';

    certifications.forEach(cert => {
      const row = `
        <tr>
          <td>${cert.certificate_name}</td>
          <td>${cert.total_donations}</td>
          <td>${new Date(cert.issued_date).toLocaleDateString()}</td>
          <td>
            <a class="btn btn-primary btn-sm" href="/api/certifications/download/${cert.certification_id}" target="_blank">
              Download
            </a>
          </td>
        </tr>
      `;
      table.innerHTML += row;
    });

  } catch (error) {
    console.error('Error loading certifications:', error);
  }
}
