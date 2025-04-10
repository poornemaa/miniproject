document.addEventListener('DOMContentLoaded', async () => {
    const token = localStorage.getItem('token');
  
    if (!token) {
      alert('Please login first.');
      window.location.href = '/';
      return;
    }
  
    try {
      const response = await fetch('/api/recipients', {
        headers: {
          'Authorization': 'Bearer ' + token
        }
      });
  
      const recipients = await response.json();
      const table = document.getElementById('recipientsTable');
      table.innerHTML = '';
  
      recipients.forEach(recipient => {
        const row = `
          <tr>
            <td>${recipient.organization_name}</td>
            <td>${recipient.contact_person}</td>
            <td>${recipient.email}</td>
            <td>${recipient.phone}</td>
            <td>${recipient.address}</td>
          </tr>
        `;
        table.innerHTML += row;
      });
  
    } catch (error) {
      console.error('Error loading recipients:', error);
    }
  });
  