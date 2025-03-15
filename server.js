// Importamos Express, un framework para construir servidores web en Node.js
const express = require("express");

// Importamos bcryptjs para encriptar contraseñas de forma segura
const bcrypt = require("bcryptjs");

// Importamos jsonwebtoken para generar y verificar tokens JWT
const jwt = require("jsonwebtoken");

//Importamos el validador
const { body, validationResult } = require("express-validator");

// Creamos una instancia de la aplicación Express
const app = express();

// Middleware para permitir el uso de JSON en las solicitudes HTTP
app.use(express.json());

// Cargamos las variables de entorno desde el archivo .env
require("dotenv").config();

// Obtenemos la clave secreta para JWT desde las variables de entorno
const SECRET_KEY = process.env.SECRET_KEY;

// Definimos el puerto en el que se ejecutará el servidor, por defecto 3000
const PORT = process.env.PORT || 3000;

// Simulamos una base de datos en memoria con un arreglo de usuarios
const users = [];

// Registro de usuario
app.post(
    "/api/auth/register",
    [
        body("name").notEmpty().withMessage("El nombre es obligatorio"),
        body("email").isEmail().withMessage("Debe ser un email válido"),
        body("password").isLength({ min: 6 }).withMessage("La contraseña debe tener al menos 6 caracteres"),
    ],
    async (req, res) => {
        // Validamos los datos recibidos
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }

        const { name, email, password } = req.body;

        // Verificar si el usuario ya existe
        if (users.find(user => user.email === email)) {
            return res.status(400).json({ message: "El usuario ya está registrado" });
        }

        // Encriptar la contraseña
        const hashedPassword = await bcrypt.hash(password, 10);

        // Guardar usuario en la "base de datos"
        const newUser = { id: users.length + 1, name, email, password: hashedPassword };
        users.push(newUser);

        res.status(201).json({ message: "Usuario registrado con éxito" });
    }
);

// Inicio de sesión
app.post("/api/auth/login", async (req, res) => {
    // Extraemos email y password del cuerpo de la solicitud
    const { email, password } = req.body;

    // Buscamos el usuario en la base de datos por su email
    const user = users.find(user => user.email === email);
    if (!user) return res.status(400).json({ message: "Usuario no encontrado" });

    // Comparamos la contraseña ingresada con la almacenada en la base de datos
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Contraseña incorrecta" });

    // Generamos un token JWT con los datos del usuario
    const token = jwt.sign(
        { id: user.id, email: user.email }, // Información dentro del token
        SECRET_KEY, // Clave secreta para firmar el token
        { expiresIn: process.env.TOKEN_EXPIRATION || "1h" } // Tiempo de expiración del token
    );

    // Enviamos el token al cliente
    res.json({ token });
});

// Obtener datos del usuario autenticado
app.get("/api/auth/me", (req, res) => {
    // Extraemos el token del header de autorización
    const token = req.headers.authorization?.split(" ")[1];

    // Si no hay token, se deniega el acceso
    if (!token) return res.status(401).json({ message: "Acceso denegado, token requerido" });

    try {
        // Verificamos y decodificamos el token
        const decoded = jwt.verify(token, SECRET_KEY);

        // Buscamos el usuario en la base de datos por su ID
        const user = users.find(user => user.id === decoded.id);
        if (!user) return res.status(404).json({ message: "Usuario no encontrado" });

        // Enviamos los datos del usuario autenticado
        res.json({ id: user.id, name: user.name, email: user.email });
    } catch (error) {
        // En caso de error, informamos que el token es inválido o ha expirado
        res.status(401).json({ message: "Token inválido o expirado" });
    }
});

// Iniciar el servidor en el puerto definido
app.listen(PORT, () => console.log(`Servidor en http://localhost:${PORT}`));
