document.getElementById('postForm').addEventListener('submit', function(event) {
    event.preventDefault();
    const formData = new FormData(this);
    fetch('/post', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        if (data.status === 'success') {
            window.location.href = '/';
        } else {
            alert(data.message);
        }
    })
    .catch(error => console.error('Error:', error));
});