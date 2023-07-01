function getPassword(encrypted, event) {
  event.preventDefault(); // stop redirect

  var csrfToken = document.querySelector('input[name="csrf_token"]').value;
  var xhr = new XMLHttpRequest();
  xhr.open("POST", "/clipboard", true);
  xhr.setRequestHeader("Content-Type", "application/json");
  xhr.setRequestHeader("X-CSRFToken", csrfToken);

  xhr.onload = function() {
    var decrypted = JSON.parse(xhr.responseText);
    navigator.clipboard.writeText(decrypted.value);
    alert("Texto copiado al portapapeles");
  };

  xhr.send(JSON.stringify({ content: encrypted }));
}
