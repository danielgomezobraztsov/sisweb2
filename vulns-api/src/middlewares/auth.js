function auth(req, res, next) {
    const authHeader = req.headers.authorization;
    const expectedToken = process.env.API_TOKEN;

    if (!expectedToken) {
        return res.status(401).json({
            codigo: 401,
            texto: "No autenticado",
            descripcion: "API_TOKEN no configurado"
        });
    }

    if (!authHeader || authHeader !== `Bearer ${expectedToken}`) {
        return res.status(401).json({
            codigo: 401,
            texto: "No autenticado",
            descripcion: "Token ausente o inválido"
        });
    }

    next();
}

module.exports = auth;