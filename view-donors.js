document.addEventListener('DOMContentLoaded', async () => {
    const token = localStorage.getItem('token');
  
    if (!token) {
      alert('Please login first.');
      window.location.href = '/';
      return;
    }
  
    try {
      const response = await fetch('/api/donors', {
        headers: {
          'Authorization': 'Bearer ' + token
        }
      });
  
      const donors = await response.json();
      const table = document.getElementById('donorsTable');
      table.innerHTML = '';
  
      donors.forEach(donor => {
        const row = `
          <tr>
            <td>${donor.organization_name}</td>
            <td>${donor.contact_person}</td>
            <td>${donor.email}</td>
            <td>${donor.phone}</td>
            <td>${donor.address}</td>
          </tr>
        `;
        table.innerHTML += row;
      });
  
    } catch (error) {
      console.error('Error loading donors:', error);
    }
  });
  