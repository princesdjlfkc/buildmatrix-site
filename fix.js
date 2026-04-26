const fs = require('fs');
let c = fs.readFileSync('server.js', 'utf8');
c = c.replace(/const ownerEmail = .*?;/, "const ownerEmail = 'princeramos231\u0040gmail.com';");
fs.writeFileSync('server.js', c, 'utf8');
console.log('Fixed!');
