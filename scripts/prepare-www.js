const fs = require('fs');
fs.mkdirSync('www', { recursive: true });
fs.copyFileSync('index.html', 'www/index.html');
console.log('www/index.html updated');
