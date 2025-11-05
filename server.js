const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Servir archivos estáticos
app.use(express.static(path.join(__dirname, '/')));

// Almacenar las salas y jugadores
const rooms = new Map();

// Manejar conexiones de Socket.IO
io.on('connection', (socket) => {
    console.log('Nuevo cliente conectado:', socket.id);

    // Unirse a una sala existente
    socket.on('joinRoom', ({ room }) => {
        if (!rooms.has(room)) {
            socket.emit('error', { message: 'La sala no existe' });
            return;
        }

        const roomData = rooms.get(room);
        
        if (roomData.players.length >= 2) {
            socket.emit('error', { message: 'La sala está llena' });
            return;
        }

        // Asignar símbolo al jugador (X o O)
        const symbol = roomData.players.length === 0 ? 'X' : 'O';
        roomData.players.push({ id: socket.id, symbol });
        
        socket.join(room);
        socket.emit('roomJoined', { room, symbol });
        
        // Si hay dos jugadores, iniciar el juego
        if (roomData.players.length === 2) {
            io.to(room).emit('gameStart', { 
                message: '¡Juego iniciado!',
                currentPlayer: 'X' 
            });
        }
    });

    // Crear una nueva sala
    socket.on('createRoom', () => {
        const roomId = generateRoomId();
        rooms.set(roomId, {
            players: [{ id: socket.id, symbol: 'X' }],
            board: Array(9).fill(''),
            currentPlayer: 'X'
        });
        
        socket.join(roomId);
        socket.emit('roomCreated', { room: roomId });
        console.log(`Sala creada: ${roomId}`);
    });

    // Manejar movimientos
    socket.on('makeMove', ({ index, room, symbol }) => {
        const roomData = rooms.get(room);
        
        if (!roomData || roomData.players.length < 2) {
            return;
        }

        // Verificar que sea el turno del jugador
        const player = roomData.players.find(p => p.id === socket.id);
        if (!player || player.symbol !== roomData.currentPlayer) {
            return;
        }

        // Actualizar el tablero
        roomData.board[index] = symbol;
        
        // Cambiar el turno
        roomData.currentPlayer = roomData.currentPlayer === 'X' ? 'O' : 'X';
        
        // Enviar la actualización a todos los jugadores en la sala
        io.to(room).emit('gameUpdate', {
            index,
            symbol,
            currentPlayer: roomData.currentPlayer
        });
    });

    // Manejar desconexión
    socket.on('disconnect', () => {
        console.log('Cliente desconectado:', socket.id);
        
        // Buscar en qué sala estaba el jugador
        for (const [roomId, roomData] of rooms.entries()) {
            const playerIndex = roomData.players.findIndex(p => p.id === socket.id);
            
            if (playerIndex !== -1) {
                // Notificar al otro jugador
                roomData.players.splice(playerIndex, 1);
                io.to(roomId).emit('playerDisconnected');
                
                // Si la sala queda vacía, eliminarla
                if (roomData.players.length === 0) {
                    rooms.delete(roomId);
                    console.log(`Sala ${roomId} eliminada por estar vacía`);
                }
                
                break;
            }
        }
    });
});

// Generar un ID de sala aleatorio
function generateRoomId() {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    let result = '';
    for (let i = 0; i < 6; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
}

// Iniciar el servidor
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Servidor ejecutándose en http://localhost:${PORT}`);
});
