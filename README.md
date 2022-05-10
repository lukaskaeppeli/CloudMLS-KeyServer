# Athena Keyserver

This project serves as backend for [CloudMLS](https://github.com/lukaskaeppeli/CloudMLS). More documentation is following...

## Installation

- Install nodejs (tested with v17.6.0), npm, git:

(Ubuntu)
```bash
$ sudo apt install nodejs npm git
```

- Install mongodb following their [installation guide](https://docs.mongodb.com/manual/installation/)

- Enable mongodb
```bash
$ systemctl start mongodb 
```

- Clone this repository:

```bash
$ git clone https://github.com/lukaskaeppeli/CloudMLS-KeyServer
```

- Install pm2:
```bash
$ sudo npm install -g pm2
```

- Create environment using the template. The default environment settings allows the server to run on your local machine. Change the variables as you wish:
```bash
$ cp .env.template .env
```


- Compile the project:
```bash
$ npm run compile-typescript
```

- Start the pm2 service:
```bash
$ pm2 start build/index.js
```