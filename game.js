// Variables del juego
let currentPlayer = 'X';
let gameActive = true;
let gameState = ['', '', '', '', '', '', '', '', ''];
let scores = { X: 0, O: 0 };
let gameMode = '';
let socket;
let roomId = '';
let playerSymbol = '';

// --- NUEVA NAVEGACIÓN ---
// Elementos del menú principal y modos
const mainMenu = document.getElementById('main-menu');
const btnBot = document.getElementById('btn-bot');
const btnOffline = document.getElementById('btn-offline');
const btnCasual = document.getElementById('btn-casual');
const btnCompetitive = document.getElementById('btn-competitive');
const btnSettings = document.getElementById('btn-settings');

const botMenu = document.getElementById('bot-menu');
const backBotMenu = document.getElementById('back-bot-menu');
const gameBot = document.getElementById('game-bot');
const gameOffline = document.getElementById('game-offline');
const gameCasual = document.getElementById('game-casual');
const gameCompetitive = document.getElementById('game-competitive');
const settingsMenu = document.getElementById('settings-menu');
const backBtns = document.querySelectorAll('.back-btn');

// --- MENÚ CASUAL ---
const casualMenu = document.getElementById('casual-menu');
const btnPublicRooms = document.getElementById('btn-public-rooms');
const btnPrivateRooms = document.getElementById('btn-private-rooms');
const backCasualMenuBtn = document.getElementById('back-casual-menu');

// --- MENÚ SALAS PÚBLICAS ---
const publicRoomsMenu = document.getElementById('public-rooms-menu');
const btnTournament = document.getElementById('btn-tournament');
const btn1v1 = document.getElementById('btn-1v1');
const backPublicRoomsBtn = document.getElementById('back-public-rooms');

// --- MENÚ SALAS PRIVADAS ---
const privateRoomsMenu = document.getElementById('private-rooms-menu');
const btnCreateRoom = document.getElementById('btn-create-room');
const btnJoinRoom = document.getElementById('btn-join-room');
const backPrivateRoomsBtn = document.getElementById('back-private-rooms');

// --- MENÚ CREACIÓN DE SALA PRIVADA ---
const createRoomMenu = document.getElementById('create-room-menu');
const btnCreateTournament = document.getElementById('btn-create-tournament');
const btnCreate1v1 = document.getElementById('btn-create-1v1');
const backCreateRoomBtn = document.getElementById('back-create-room');

// --- BOT: Selección de dificultad ---
let selectedBotDifficulty = null;
const botEasyBtn = document.getElementById('bot-easy');
const botMediumBtn = document.getElementById('bot-medium');
const botHardBtn = document.getElementById('bot-hard');
const botImpossibleBtn = document.getElementById('bot-impossible');

// --- OFFLINE GAME ---
let offlineGameBoard = Array(9).fill('');
let offlineGameActive = false;
let offlineCurrentPlayer = 'X';
let offlineStartingPlayer = 'X';
let offlineScore = { X: 0, O: 0 };

const offlineCells = document.querySelectorAll('#offline-board .cell');
const offlineStatus = document.getElementById('offline-status');
const offlineTurnSpan = document.getElementById('offline-turn');
const offlineRestartBtn = document.getElementById('offline-restart');
const backOfflineGameBtn = document.getElementById('back-offline-game');
const offlineGameTitle = document.getElementById('offline-game-title');
const offlineScoreX = document.getElementById('offline-score-x');
const offlineScoreO = document.getElementById('offline-score-o');

function startOfflineGame() {
    offlineGameTitle.textContent = `👥 Modo Offline`;
    switchMenu(document.getElementById('game-offline'));
    resetOfflineBoard();
}

function resetOfflineBoard() {
    offlineGameBoard = Array(9).fill('');
    offlineGameActive = true;
    // Alternar el jugador inicial
    offlineStartingPlayer = offlineStartingPlayer === 'X' ? 'O' : 'X';
    offlineCurrentPlayer = offlineStartingPlayer;
    offlineStatus.textContent = 'Turno de: ';
    offlineTurnSpan.textContent = offlineCurrentPlayer;
    offlineCells.forEach(cell => {
        cell.textContent = '';
        cell.classList.remove('win');
        cell.classList.remove('draw');
        cell.classList.remove('x-color');
        cell.classList.remove('o-color');
        cell.style.pointerEvents = 'auto';
    });
}

function endOfflineGame(result, winLine) {
    offlineGameActive = false;
    if (result === 'X') {
        offlineScore.X++;
        offlineStatus.textContent = '¡Gana Jugador X! 🎉';
        if (winLine) winLine.forEach(i => offlineCells[i].classList.add('win'));
    } else if (result === 'O') {
        offlineScore.O++;
        offlineStatus.textContent = '¡Gana Jugador O! 🎉';
        if (winLine) winLine.forEach(i => offlineCells[i].classList.add('win'));
    } else {
        offlineStatus.textContent = 'Empate 🤝';
        offlineCells.forEach(cell => cell.classList.add('draw'));
    }
    offlineScoreX.textContent = offlineScore.X;
    offlineScoreO.textContent = offlineScore.O;
    offlineCells.forEach(cell => cell.style.pointerEvents = 'none');
}

function offlineCellClick(e) {
    const idx = Number(e.target.dataset.index);
    if (!offlineGameActive || offlineGameBoard[idx] !== '') return;
    offlineGameBoard[idx] = offlineCurrentPlayer;
    e.target.textContent = offlineCurrentPlayer;
    e.target.classList.remove('x-color', 'o-color');
    if (offlineCurrentPlayer === 'X') {
        e.target.classList.add('x-color');
    } else {
        e.target.classList.add('o-color');
    }
    // ¿Ganó alguien?
    let winner = null;
    let winLine = null;
    for (const cond of winConditions) {
        const [a, b, c] = cond;
        if (offlineGameBoard[a] && offlineGameBoard[a] === offlineGameBoard[b] && offlineGameBoard[a] === offlineGameBoard[c]) {
            winner = offlineGameBoard[a];
            winLine = cond;
            break;
        }
    }
    if (winner) return endOfflineGame(winner, winLine);
    if (!offlineGameBoard.includes('')) return endOfflineGame('draw');
    // Cambiar turno
    offlineCurrentPlayer = offlineCurrentPlayer === 'X' ? 'O' : 'X';
    offlineStatus.textContent = 'Turno de: ';
    offlineTurnSpan.textContent = offlineCurrentPlayer;
}

offlineCells.forEach(cell => cell.addEventListener('click', offlineCellClick));
offlineRestartBtn.addEventListener('click', resetOfflineBoard);
backOfflineGameBtn.addEventListener('click', goBack);

// --- BOT GAME IMPOSSIBLE ---
let botImpossibleGameBoard = Array(9).fill('');
let botImpossibleGameActive = false;
let botImpossibleCurrentPlayer = 'X';

const botImpossibleCells = document.querySelectorAll('#bot-impossible-board .cell');
const botImpossibleStatus = document.getElementById('bot-impossible-status');
const botImpossibleTurnSpan = document.getElementById('bot-impossible-turn');
const botImpossibleRestartBtn = document.getElementById('bot-impossible-restart');
const backBotImpossibleGameBtn = document.getElementById('back-bot-impossible-game');
const botImpossibleGameTitle = document.getElementById('bot-impossible-game-title');

function startBotImpossibleGame() {
    botImpossibleGameTitle.textContent = `🤖 Modo Imposible (vs BOT)`;
    switchMenu(document.getElementById('game-bot-impossible'));
    resetBotImpossibleBoard();
}

function resetBotImpossibleBoard() {
    botImpossibleGameBoard = Array(9).fill('');
    botImpossibleGameActive = true;
    botImpossibleCurrentPlayer = 'X';
    botImpossibleStatus.textContent = 'Turno de: ';
    botImpossibleTurnSpan.textContent = botImpossibleCurrentPlayer;
    botImpossibleCells.forEach(cell => {
        cell.textContent = '';
        cell.classList.remove('win');
        cell.classList.remove('draw');
        cell.style.pointerEvents = 'auto';
    });
}

function minimax(board, isMaximizing) {
    // Comprobar ganador
    for (const cond of winConditions) {
        const [a, b, c] = cond;
        if (board[a] && board[a] === board[b] && board[a] === board[c]) {
            if (board[a] === 'O') return { score: 1 };
            if (board[a] === 'X') return { score: -1 };
        }
    }
    if (!board.includes('')) return { score: 0 };
    // Recursión
    if (isMaximizing) {
        let bestScore = -Infinity;
        let move = -1;
        for (let i = 0; i < 9; i++) {
            if (board[i] === '') {
                board[i] = 'O';
                let score = minimax(board, false).score;
                board[i] = '';
                if (score > bestScore) {
                    bestScore = score;
                    move = i;
                }
            }
        }
        return { score: bestScore, move };
    } else {
        let bestScore = Infinity;
        let move = -1;
        for (let i = 0; i < 9; i++) {
            if (board[i] === '') {
                board[i] = 'X';
                let score = minimax(board, true).score;
                board[i] = '';
                if (score < bestScore) {
                    bestScore = score;
                    move = i;
                }
            }
        }
        return { score: bestScore, move };
    }
}

function botImpossibleMove() {
    const result = minimax([...botImpossibleGameBoard], true);
    if (typeof result.move === 'number') {
        botImpossibleGameBoard[result.move] = 'O';
        botImpossibleCells[result.move].textContent = 'O';
    }
}

function endBotImpossibleGame(result, winLine) {
    botImpossibleGameActive = false;
    if (result === 'X') {
        botImpossibleStatus.textContent = '¡Has ganado! 🎉';
        if (winLine) winLine.forEach(i => botImpossibleCells[i].classList.add('win'));
    } else if (result === 'O') {
        botImpossibleStatus.textContent = '¡El BOT gana! 🤖';
        if (winLine) winLine.forEach(i => botImpossibleCells[i].classList.add('win'));
    } else {
        botImpossibleStatus.textContent = 'Empate 🤝';
        botImpossibleCells.forEach(cell => cell.classList.add('draw'));
    }
    botImpossibleCells.forEach(cell => cell.style.pointerEvents = 'none');
}

function botImpossibleCellClick(e) {
    const idx = Number(e.target.dataset.index);
    if (!botImpossibleGameActive || botImpossibleGameBoard[idx] !== '') return;
    botImpossibleGameBoard[idx] = 'X';
    e.target.textContent = 'X';
    // ¿Ganó el jugador?
    let winner = null;
    let winLine = null;
    for (const cond of winConditions) {
        const [a, b, c] = cond;
        if (botImpossibleGameBoard[a] && botImpossibleGameBoard[a] === botImpossibleGameBoard[b] && botImpossibleGameBoard[a] === botImpossibleGameBoard[c]) {
            winner = botImpossibleGameBoard[a];
            winLine = cond;
            break;
        }
    }
    if (winner) return endBotImpossibleGame(winner, winLine);
    if (!botImpossibleGameBoard.includes('')) return endBotImpossibleGame('draw');
    // Turno del bot
    botImpossibleCurrentPlayer = 'O';
    botImpossibleStatus.textContent = 'Turno de: ';
    botImpossibleTurnSpan.textContent = botImpossibleCurrentPlayer;
    setTimeout(() => {
        botImpossibleMove();
        // ¿Ganó el bot?
        let winner = null;
        let winLine = null;
        for (const cond of winConditions) {
            const [a, b, c] = cond;
            if (botImpossibleGameBoard[a] && botImpossibleGameBoard[a] === botImpossibleGameBoard[b] && botImpossibleGameBoard[a] === botImpossibleGameBoard[c]) {
                winner = botImpossibleGameBoard[a];
                winLine = cond;
                break;
            }
        }
        if (winner) return endBotImpossibleGame(winner, winLine);
        if (!botImpossibleGameBoard.includes('')) return endBotImpossibleGame('draw');
        // Vuelve el jugador
        botImpossibleCurrentPlayer = 'X';
        botImpossibleStatus.textContent = 'Turno de: ';
        botImpossibleTurnSpan.textContent = botImpossibleCurrentPlayer;
    }, 500);
}

botImpossibleCells.forEach(cell => cell.addEventListener('click', botImpossibleCellClick));
botImpossibleRestartBtn.addEventListener('click', resetBotImpossibleBoard);
backBotImpossibleGameBtn.addEventListener('click', goBack);

// --- BOT GAME HARD ---
let botHardGameBoard = Array(9).fill('');
let botHardGameActive = false;
let botHardCurrentPlayer = 'X';

const botHardCells = document.querySelectorAll('#bot-hard-board .cell');
const botHardStatus = document.getElementById('bot-hard-status');
const botHardTurnSpan = document.getElementById('bot-hard-turn');
const botHardRestartBtn = document.getElementById('bot-hard-restart');
const backBotHardGameBtn = document.getElementById('back-bot-hard-game');
const botHardGameTitle = document.getElementById('bot-hard-game-title');

function startBotHardGame() {
    botHardGameTitle.textContent = `🤖 Modo Difícil (vs BOT)`;
    switchMenu(document.getElementById('game-bot-hard'));
    resetBotHardBoard();
}

function resetBotHardBoard() {
    botHardGameBoard = Array(9).fill('');
    botHardGameActive = true;
    botHardCurrentPlayer = 'X';
    botHardStatus.textContent = 'Turno de: ';
    botHardTurnSpan.textContent = botHardCurrentPlayer;
    botHardCells.forEach(cell => {
        cell.textContent = '';
        cell.classList.remove('win');
        cell.classList.remove('draw');
        cell.style.pointerEvents = 'auto';
    });
}

function botHardMove() {
    // 80% óptimo (gana o bloquea), 20% aleatorio
    if (Math.random() > 0.8) {
        // Aleatorio
        const empty = botHardGameBoard.map((v,i) => v === '' ? i : null).filter(i => i !== null);
        if (empty.length === 0) return;
        const move = empty[Math.floor(Math.random() * empty.length)];
        botHardGameBoard[move] = 'O';
        botHardCells[move].textContent = 'O';
        return;
    }
    // Intenta ganar
    for (const cond of winConditions) {
        const [a, b, c] = cond;
        const line = [botHardGameBoard[a], botHardGameBoard[b], botHardGameBoard[c]];
        if (line.filter(x => x === 'O').length === 2 && line.includes('')) {
            const idx = cond[line.indexOf('')];
            botHardGameBoard[idx] = 'O';
            botHardCells[idx].textContent = 'O';
            return;
        }
    }
    // Intenta bloquear
    for (const cond of winConditions) {
        const [a, b, c] = cond;
        const line = [botHardGameBoard[a], botHardGameBoard[b], botHardGameBoard[c]];
        if (line.filter(x => x === 'X').length === 2 && line.includes('')) {
            const idx = cond[line.indexOf('')];
            botHardGameBoard[idx] = 'O';
            botHardCells[idx].textContent = 'O';
            return;
        }
    }
    // Si no, aleatorio
    const empty = botHardGameBoard.map((v,i) => v === '' ? i : null).filter(i => i !== null);
    if (empty.length === 0) return;
    const move = empty[Math.floor(Math.random() * empty.length)];
    botHardGameBoard[move] = 'O';
    botHardCells[move].textContent = 'O';
}

function endBotHardGame(result, winLine) {
    botHardGameActive = false;
    if (result === 'X') {
        botHardStatus.textContent = '¡Has ganado! 🎉';
        if (winLine) winLine.forEach(i => botHardCells[i].classList.add('win'));
    } else if (result === 'O') {
        botHardStatus.textContent = '¡El BOT gana! 🤖';
        if (winLine) winLine.forEach(i => botHardCells[i].classList.add('win'));
    } else {
        botHardStatus.textContent = 'Empate 🤝';
        botHardCells.forEach(cell => cell.classList.add('draw'));
    }
    botHardCells.forEach(cell => cell.style.pointerEvents = 'none');
}

function botHardCellClick(e) {
    const idx = Number(e.target.dataset.index);
    if (!botHardGameActive || botHardGameBoard[idx] !== '') return;
    botHardGameBoard[idx] = 'X';
    e.target.textContent = 'X';
    // ¿Ganó el jugador?
    let winner = null;
    let winLine = null;
    for (const cond of winConditions) {
        const [a, b, c] = cond;
        if (botHardGameBoard[a] && botHardGameBoard[a] === botHardGameBoard[b] && botHardGameBoard[a] === botHardGameBoard[c]) {
            winner = botHardGameBoard[a];
            winLine = cond;
            break;
        }
    }
    if (winner) return endBotHardGame(winner, winLine);
    if (!botHardGameBoard.includes('')) return endBotHardGame('draw');
    // Turno del bot
    botHardCurrentPlayer = 'O';
    botHardStatus.textContent = 'Turno de: ';
    botHardTurnSpan.textContent = botHardCurrentPlayer;
    setTimeout(() => {
        botHardMove();
        // ¿Ganó el bot?
        let winner = null;
        let winLine = null;
        for (const cond of winConditions) {
            const [a, b, c] = cond;
            if (botHardGameBoard[a] && botHardGameBoard[a] === botHardGameBoard[b] && botHardGameBoard[a] === botHardGameBoard[c]) {
                winner = botHardGameBoard[a];
                winLine = cond;
                break;
            }
        }
        if (winner) return endBotHardGame(winner, winLine);
        if (!botHardGameBoard.includes('')) return endBotHardGame('draw');
        // Vuelve el jugador
        botHardCurrentPlayer = 'X';
        botHardStatus.textContent = 'Turno de: ';
        botHardTurnSpan.textContent = botHardCurrentPlayer;
    }, 500);
}

botHardCells.forEach(cell => cell.addEventListener('click', botHardCellClick));
botHardRestartBtn.addEventListener('click', resetBotHardBoard);
backBotHardGameBtn.addEventListener('click', goBack);

// --- BOT GAME MEDIUM ---
let botMediumGameBoard = Array(9).fill('');
let botMediumGameActive = false;
let botMediumCurrentPlayer = 'X';

const botMediumCells = document.querySelectorAll('#bot-medium-board .cell');
const botMediumStatus = document.getElementById('bot-medium-status');
const botMediumTurnSpan = document.getElementById('bot-medium-turn');
const botMediumRestartBtn = document.getElementById('bot-medium-restart');
const backBotMediumGameBtn = document.getElementById('back-bot-medium-game');
const botMediumGameTitle = document.getElementById('bot-medium-game-title');

function startBotMediumGame() {
    botMediumGameTitle.textContent = `🤖 Modo Medio (vs BOT)`;
    switchMenu(document.getElementById('game-bot-medium'));
    resetBotMediumBoard();
}

function resetBotMediumBoard() {
    botMediumGameBoard = Array(9).fill('');
    botMediumGameActive = true;
    botMediumCurrentPlayer = 'X';
    botMediumStatus.textContent = 'Turno de: ';
    botMediumTurnSpan.textContent = botMediumCurrentPlayer;
    botMediumCells.forEach(cell => {
        cell.textContent = '';
        cell.classList.remove('win');
        cell.classList.remove('draw');
        cell.style.pointerEvents = 'auto';
    });
}

function botMediumMove() {
    // 50% aleatorio, 50% bloquea o gana
    if (Math.random() < 0.5) {
        // Aleatorio
        const empty = botMediumGameBoard.map((v,i) => v === '' ? i : null).filter(i => i !== null);
        if (empty.length === 0) return;
        const move = empty[Math.floor(Math.random() * empty.length)];
        botMediumGameBoard[move] = 'O';
        botMediumCells[move].textContent = 'O';
        return;
    }
    // Intenta ganar
    for (const cond of winConditions) {
        const [a, b, c] = cond;
        const line = [botMediumGameBoard[a], botMediumGameBoard[b], botMediumGameBoard[c]];
        if (line.filter(x => x === 'O').length === 2 && line.includes('')) {
            const idx = cond[line.indexOf('')];
            botMediumGameBoard[idx] = 'O';
            botMediumCells[idx].textContent = 'O';
            return;
        }
    }
    // Intenta bloquear
    for (const cond of winConditions) {
        const [a, b, c] = cond;
        const line = [botMediumGameBoard[a], botMediumGameBoard[b], botMediumGameBoard[c]];
        if (line.filter(x => x === 'X').length === 2 && line.includes('')) {
            const idx = cond[line.indexOf('')];
            botMediumGameBoard[idx] = 'O';
            botMediumCells[idx].textContent = 'O';
            return;
        }
    }
    // Si no, aleatorio
    const empty = botMediumGameBoard.map((v,i) => v === '' ? i : null).filter(i => i !== null);
    if (empty.length === 0) return;
    const move = empty[Math.floor(Math.random() * empty.length)];
    botMediumGameBoard[move] = 'O';
    botMediumCells[move].textContent = 'O';
}

function endBotMediumGame(result, winLine) {
    botMediumGameActive = false;
    if (result === 'X') {
        botMediumStatus.textContent = '¡Has ganado! 🎉';
        if (winLine) winLine.forEach(i => botMediumCells[i].classList.add('win'));
    } else if (result === 'O') {
        botMediumStatus.textContent = '¡El BOT gana! 🤖';
        if (winLine) winLine.forEach(i => botMediumCells[i].classList.add('win'));
    } else {
        botMediumStatus.textContent = 'Empate 🤝';
        botMediumCells.forEach(cell => cell.classList.add('draw'));
    }
    botMediumCells.forEach(cell => cell.style.pointerEvents = 'none');
}

function botMediumCellClick(e) {
    const idx = Number(e.target.dataset.index);
    if (!botMediumGameActive || botMediumGameBoard[idx] !== '') return;
    botMediumGameBoard[idx] = 'X';
    e.target.textContent = 'X';
    // ¿Ganó el jugador?
    let winner = null;
    let winLine = null;
    for (const cond of winConditions) {
        const [a, b, c] = cond;
        if (botMediumGameBoard[a] && botMediumGameBoard[a] === botMediumGameBoard[b] && botMediumGameBoard[a] === botMediumGameBoard[c]) {
            winner = botMediumGameBoard[a];
            winLine = cond;
            break;
        }
    }
    if (winner) return endBotMediumGame(winner, winLine);
    if (!botMediumGameBoard.includes('')) return endBotMediumGame('draw');
    // Turno del bot
    botMediumCurrentPlayer = 'O';
    botMediumStatus.textContent = 'Turno de: ';
    botMediumTurnSpan.textContent = botMediumCurrentPlayer;
    setTimeout(() => {
        botMediumMove();
        // ¿Ganó el bot?
        let winner = null;
        let winLine = null;
        for (const cond of winConditions) {
            const [a, b, c] = cond;
            if (botMediumGameBoard[a] && botMediumGameBoard[a] === botMediumGameBoard[b] && botMediumGameBoard[a] === botMediumGameBoard[c]) {
                winner = botMediumGameBoard[a];
                winLine = cond;
                break;
            }
        }
        if (winner) return endBotMediumGame(winner, winLine);
        if (!botMediumGameBoard.includes('')) return endBotMediumGame('draw');
        // Vuelve el jugador
        botMediumCurrentPlayer = 'X';
        botMediumStatus.textContent = 'Turno de: ';
        botMediumTurnSpan.textContent = botMediumCurrentPlayer;
    }, 500);
}

botMediumCells.forEach(cell => cell.addEventListener('click', botMediumCellClick));
botMediumRestartBtn.addEventListener('click', resetBotMediumBoard);
backBotMediumGameBtn.addEventListener('click', goBack);

// --- BOT GAME EASY ---
let botGameBoard = Array(9).fill('');
let botGameActive = false;
let botCurrentPlayer = 'X';

const botCells = document.querySelectorAll('#bot-board .cell');
const botStatus = document.getElementById('bot-status');
const botTurnSpan = document.getElementById('bot-turn');
const botRestartBtn = document.getElementById('bot-restart');
const backBotGameBtn = document.getElementById('back-bot-game');
const botGameTitle = document.getElementById('bot-game-title');

function startBotGame(difficulty) {
    selectedBotDifficulty = difficulty;
    // Cambiar título según dificultad
    let label = 'Fácil';
    if (difficulty === 'medium') label = 'Medio';
    if (difficulty === 'hard') label = 'Difícil';
    if (difficulty === 'impossible') label = 'Imposible';
    botGameTitle.textContent = `🤖 Modo ${label} (vs BOT)`;
    switchMenu(gameBot);
    resetBotBoard();
}

function resetBotBoard() {
    botGameBoard = Array(9).fill('');
    botGameActive = true;
    botCurrentPlayer = 'X';
    botStatus.textContent = 'Turno de: ';
    botTurnSpan.textContent = botCurrentPlayer;
    botCells.forEach(cell => {
        cell.textContent = '';
        cell.classList.remove('win');
        cell.classList.remove('draw');
        cell.style.pointerEvents = 'auto';
    });
}

function botEasyMove() {
    // Elige una casilla vacía aleatoria
    const empty = botGameBoard.map((v,i) => v === '' ? i : null).filter(i => i !== null);
    if (empty.length === 0) return;
    const move = empty[Math.floor(Math.random() * empty.length)];
    botGameBoard[move] = 'O';
    botCells[move].textContent = 'O';
}

function checkBotWinner(board) {
    for (const cond of winConditions) {
        const [a, b, c] = cond;
        if (board[a] && board[a] === board[b] && board[a] === board[c]) {
            return board[a];
        }
    }
    return board.includes('') ? null : 'draw';
}

function endBotGame(result, winLine) {
    botGameActive = false;
    if (result === 'X') {
        botStatus.textContent = '¡Has ganado! 🎉';
        if (winLine) winLine.forEach(i => botCells[i].classList.add('win'));
    } else if (result === 'O') {
        botStatus.textContent = '¡El BOT gana! 🤖';
        if (winLine) winLine.forEach(i => botCells[i].classList.add('win'));
    } else {
        botStatus.textContent = 'Empate 🤝';
        botCells.forEach(cell => cell.classList.add('draw'));
    }
    botCells.forEach(cell => cell.style.pointerEvents = 'none');
}

function botGameCellClick(e) {
    const idx = Number(e.target.dataset.index);
    if (!botGameActive || botGameBoard[idx] !== '') return;
    botGameBoard[idx] = 'X';
    e.target.textContent = 'X';
    // ¿Ganó el jugador?
    let winner = null;
    let winLine = null;
    for (const cond of winConditions) {
        const [a, b, c] = cond;
        if (botGameBoard[a] && botGameBoard[a] === botGameBoard[b] && botGameBoard[a] === botGameBoard[c]) {
            winner = botGameBoard[a];
            winLine = cond;
            break;
        }
    }
    if (winner) return endBotGame(winner, winLine);
    if (!botGameBoard.includes('')) return endBotGame('draw');
    // Turno del bot
    botCurrentPlayer = 'O';
    botStatus.textContent = 'Turno de: ';
    botTurnSpan.textContent = botCurrentPlayer;
    setTimeout(() => {
        botEasyMove();
        // ¿Ganó el bot?
        let winner = null;
        let winLine = null;
        for (const cond of winConditions) {
            const [a, b, c] = cond;
            if (botGameBoard[a] && botGameBoard[a] === botGameBoard[b] && botGameBoard[a] === botGameBoard[c]) {
                winner = botGameBoard[a];
                winLine = cond;
                break;
            }
        }
        if (winner) return endBotGame(winner, winLine);
        if (!botGameBoard.includes('')) return endBotGame('draw');
        // Vuelve el jugador
        botCurrentPlayer = 'X';
        botStatus.textContent = 'Turno de: ';
        botTurnSpan.textContent = botCurrentPlayer;
    }, 500);
}

botCells.forEach(cell => cell.addEventListener('click', botGameCellClick));
botRestartBtn.addEventListener('click', resetBotBoard);
backBotGameBtn.addEventListener('click', goBack);


botEasyBtn.addEventListener('click', () => startBotGame('easy'));
botMediumBtn.addEventListener('click', startBotMediumGame);
botHardBtn.addEventListener('click', startBotHardGame);
botImpossibleBtn.addEventListener('click', startBotImpossibleGame);

// Estructura base para la IA de cada dificultad
function botMoveEasy(board) {
    // Selecciona una casilla vacía aleatoria
}
function botMoveMedium(board) {
    // 50% aleatorio, 50% bloquea si puede
}
function botMoveHard(board) {
    // Prioriza ganar/bloquear, pero puede fallar
}
function botMoveImpossible(board) {
    // Algoritmo minimax
}

// Navegación optimizada entre menús con animación
let currentMenu = mainMenu;
mainMenu.classList.add('active'); // Asegura que el menú principal esté activo al inicio
let navigationStack = [];

function switchMenu(targetMenu) {
    if (currentMenu === targetMenu) return;
    navigationStack.push(currentMenu); // Guarda el menú anterior
    // Oculta el menú actual con animación fade-out
    currentMenu.classList.remove('active');
    currentMenu.classList.remove('fade-in');
    currentMenu.classList.add('fade-out');
    setTimeout(() => {
        currentMenu.classList.remove('fade-out');
        // Muestra el nuevo menú con animación fade-in
        targetMenu.classList.add('active');
        targetMenu.classList.add('fade-in');
        setTimeout(() => {
            targetMenu.classList.remove('fade-in');
        }, 200);
        currentMenu = targetMenu;
    }, 200);
}

function goBack() {
    if (navigationStack.length === 0) return;
    const previousMenu = navigationStack.pop();
    // Cierra el actual y muestra el anterior
    currentMenu.classList.remove('active');
    currentMenu.classList.remove('fade-in');
    currentMenu.classList.add('fade-out');
    setTimeout(() => {
        currentMenu.classList.remove('fade-out');
        previousMenu.classList.add('active');
        previousMenu.classList.add('fade-in');
        setTimeout(() => {
            previousMenu.classList.remove('fade-in');
        }, 200);
        currentMenu = previousMenu;
    }, 200);
}

function showMainMenu() {
    switchMenu(mainMenu);
}


// Eventos de navegación
// Eventos de navegación
btnBot.addEventListener('click', () => switchMenu(botMenu));
backBotMenu.addEventListener('click', goBack);
btnOffline.addEventListener('click', startOfflineGame);
btnCasual.addEventListener('click', () => switchMenu(casualMenu));
btnCompetitive.addEventListener('click', () => switchMenu(gameCompetitive));
btnSettings.addEventListener('click', () => switchMenu(settingsMenu));
backCasualMenuBtn.addEventListener('click', goBack);

// Manejar clics en las opciones del menú casual
btnPublicRooms.addEventListener('click', () => {
    switchMenu(publicRoomsMenu);
});

btnPrivateRooms.addEventListener('click', () => {
    switchMenu(privateRoomsMenu);
});

// Manejar clics en las opciones del menú de salas públicas
btnTournament.addEventListener('click', () => {
    console.log('Iniciando búsqueda de torneo...');
    // Aquí irá la lógica para buscar partida de torneo
});

btn1v1.addEventListener('click', () => {
    console.log('Buscando partida 1v1...');
    // Aquí irá la lógica para buscar partida 1v1
});

// Manejadores de los botones de salas privadas
btnCreateRoom.addEventListener('click', () => {
    switchMenu(createRoomMenu);
});

btnJoinRoom.addEventListener('click', () => {
    console.log('Uniéndose a sala privada...');
    // Aquí irá la lógica para unirse a una sala privada
});

// Manejadores de los botones de creación de sala
btnCreateTournament.addEventListener('click', () => {
    console.log('Creando torneo privado...');
    // Aquí irá la lógica para crear un torneo privado
});

btnCreate1v1.addEventListener('click', () => {
    console.log('Creando sala 1v1 privada...');
    // Aquí irá la lógica para crear una sala 1v1 privada
});

// Manejadores de los botones de volver
backPublicRoomsBtn.addEventListener('click', goBack);
backPrivateRoomsBtn.addEventListener('click', goBack);
backCreateRoomBtn.addEventListener('click', goBack);

// --- FIN NUEVA NAVEGACIÓN ---

// Elementos del DOM
const cells = document.querySelectorAll('.cell');
const statusDisplay = document.getElementById('status');
const scoreXElement = document.getElementById('score-x');
const scoreOElement = document.getElementById('score-o');
const gameSection = document.getElementById('game');
const localModeBtn = document.getElementById('local-mode');
const onlineModeBtn = document.getElementById('online-mode');
const onlineOptions = document.getElementById('online-options');
const createRoomBtn = document.getElementById('create-room');
const joinRoomBtn = document.getElementById('join-room');
const roomIdInput = document.getElementById('room-id');
const resetBtn = document.getElementById('reset');

// Combinaciones ganadoras
const winConditions = [
    [0, 1, 2], [3, 4, 5], [6, 7, 8], // Filas
    [0, 3, 6], [1, 4, 7], [2, 5, 8], // Columnas
    [0, 4, 8], [2, 4, 6]             // Diagonales
];

// Inicialización del juego
function initGame() {
    gameState = ['', '', '', '', '', '', '', '', ''];
    gameActive = true;
    currentPlayer = 'X';
    updateStatus(`🔴 TURNO DE: ${currentPlayer}`);
    
    // Limpiar el tablero
    cells.forEach(cell => {
        cell.textContent = '';
        cell.classList.remove('x', 'o', 'winner');
    });
    
    // Limpiar confeti existente
    const canvas = document.querySelector('canvas');
    if (canvas) {
        const context = canvas.getContext('2d');
        context.clearRect(0, 0, canvas.width, canvas.height);
    }
}

// Manejar clic en una celda
function handleCellClick(e) {
    const clickedCell = e.target;
    const clickedCellIndex = parseInt(clickedCell.getAttribute('data-index'));

    // Verificar si la celda ya está ocupada o el juego no está activo
    if (gameState[clickedCellIndex] !== '' || !gameActive) {
        return;
    }

    // Efecto de sonido
    playSound('move');

    // Efecto visual al hacer clic
    clickedCell.style.transform = 'scale(0.9)';
    setTimeout(() => {
        clickedCell.style.transform = 'scale(1)';
    }, 100);

    // Actualizar el estado del juego
    gameState[clickedCellIndex] = currentPlayer;
    clickedCell.textContent = currentPlayer;
    clickedCell.classList.add(currentPlayer.toLowerCase());

    // En modo online, enviar el movimiento al servidor
    if (gameMode === 'online' && socket) {
        socket.emit('makeMove', { 
            index: clickedCellIndex, 
            room: roomId,
            symbol: playerSymbol
        });
    }

    // Verificar si hay un ganador o empate
    checkResult();
}

// Actualizar el estado del juego
function updateStatus(message) {
    statusDisplay.textContent = message;
    // Efecto de máquina de escribir
    const text = statusDisplay.textContent;
    statusDisplay.textContent = '';
    let i = 0;
    const speed = 30; // Velocidad de la animación en ms
    
    function typeWriter() {
        if (i < text.length) {
            statusDisplay.textContent += text.charAt(i);
            i++;
            setTimeout(typeWriter, speed);
        }
    }
    
    typeWriter();
}

// Verificar el resultado del juego
function checkResult() {
    let roundWon = false;
    
    // Verificar combinaciones ganadoras
    for (let i = 0; i < winConditions.length; i++) {
        const [a, b, c] = winConditions[i];
        if (gameState[a] === '' || gameState[a] !== gameState[b] || gameState[a] !== gameState[c]) {
            continue;
        }
        
        // Hay un ganador
        roundWon = true;
        gameActive = false;
        
        // Resaltar las celdas ganadoras
        cells[a].classList.add('winner');
        cells[b].classList.add('winner');
        cells[c].classList.add('winner');
        
        // Actualizar puntuación
        scores[gameState[a]]++;
        updateScore();
        
        // Efecto de sonido de victoria
        playSound('win');
        
        // Efecto de confeti
        triggerConfetti();
        
        // Mostrar mensaje de victoria
        updateStatus(`🏆 ¡JUGADOR ${gameState[a]} GANA!`);
        break;
    }
    
    // Verificar empate
    if (!roundWon && !gameState.includes('')) {
        gameActive = false;
        updateStatus('🤝 ¡EMPATE!');
        playSound('draw');
    }
    
    // Cambiar de jugador si el juego continúa
    if (gameActive) {
        currentPlayer = currentPlayer === 'X' ? 'O' : 'X';
        updateStatus(`🔴 TURNO DE: ${currentPlayer}`);
    }
}

// Actualizar el marcador
function updateScore() {
    scoreXElement.textContent = scores.X;
    scoreOElement.textContent = scores.O;
}

// Efecto de confeti mejorado
function triggerConfetti() {
    // Limpiar cualquier confeti existente
    const canvas = document.querySelector('canvas');
    if (canvas) {
        const context = canvas.getContext('2d');
        context.clearRect(0, 0, canvas.width, canvas.height);
    }
    
    const colors = ['#ff6b6b', '#6bffb8', '#6b8cff', '#ffd166', '#ff6bff', '#6bffff'];
    const shapes = ['square', 'circle'];
    const confettiTypes = [
        { type: 'rect', weight: 1 },
        { type: 'circle', weight: 1 },
        { type: 'star', weight: 0.3 },
        { type: 'heart', weight: 0.2 }
    ];
    
    function randomInRange(min, max) {
        return Math.random() * (max - min) + min;
    }
    
    function getRandomConfettiType() {
        const totalWeight = confettiTypes.reduce((sum, type) => sum + type.weight, 0);
        let random = Math.random() * totalWeight;
        
        for (const type of confettiTypes) {
            if (random < type.weight) return type.type;
            random -= type.weight;
        }
        
        return confettiTypes[0].type;
    }
    
    // Configuración del confeti
    const duration = 4 * 1000;
    const animationEnd = Date.now() + duration;
    const defaults = { 
        startVelocity: 25, 
        spread: 360, 
        ticks: 100, 
        zIndex: 1000,
        particleCount: 80,
        origin: { y: 0.6 },
        gravity: 0.5,
        scalar: 1.2,
        shapes: shapes,
        colors: colors,
        shape: getRandomConfettiType
    };
    
    // Función para disparar confeti desde una posición específica
    function shootConfetti(originX, originY, angleRange, count = 50) {
        confetti({
            ...defaults,
            particleCount: count,
            angle: randomInRange(angleRange[0], angleRange[1]),
            origin: { x: originX, y: originY },
            ticks: 150,
            startVelocity: randomInRange(20, 35)
        });
    }
    
    // Disparar confeti desde múltiples posiciones
    const positions = [
        { x: 0, y: 0.8, angle: [55, 125], count: 80 },
        { x: 1, y: 0.8, angle: [55, 125], count: 80 },
        { x: 0.5, y: 0.5, angle: [0, 180], count: 100 },
        { x: 0.2, y: 0.9, angle: [30, 100], count: 60 },
        { x: 0.8, y: 0.9, angle: [80, 150], count: 60 }
    ];
    
    // Disparar confeti inicial
    positions.forEach((pos, index) => {
        setTimeout(() => {
            shootConfetti(pos.x, pos.y, pos.angle, pos.count);
        }, index * 150);
    });
    
    // Disparar confeti en ráfagas aleatorias
    const burstCount = 8;
    for (let i = 0; i < burstCount; i++) {
        setTimeout(() => {
            const x = Math.random();
            const y = 0.5 + Math.random() * 0.5; // Disparar desde la mitad inferior
            shootConfetti(x, y, [60, 120], 40);
        }, 1000 + i * 400);
    }
    
    // Disparar confeti en forma de arco continuo
    const interval = setInterval(() => {
        const timeLeft = animationEnd - Date.now();
        
        if (timeLeft <= 0) {
            return clearInterval(interval);
        }
        
        // Disparar desde posiciones aleatorias en la parte inferior
        if (Math.random() > 0.3) { // 70% de probabilidad de disparar en cada intervalo
            const x = Math.random();
            confetti({
                ...defaults,
                particleCount: 3,
                angle: randomInRange(60, 120),
                startVelocity: randomInRange(15, 25),
                spread: 30,
                origin: { x, y: 0.8 },
                colors: [colors[Math.floor(Math.random() * colors.length)]],
                shape: shapes[Math.floor(Math.random() * shapes.length)]
            });
        }
    }, 100);
    
    // Limpiar después de que termine la animación
    setTimeout(() => {
        clearInterval(interval);
    }, duration);
}

// Efectos de sonido
function playSound(type) {
    if (type === 'win') {
        // Sonido de victoria (puedes reemplazar con un sonido real)
        const winSound = new Audio('data:audio/wav;base64,UklGRl9vT19XQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YU' + 
            'A'.repeat(1000));
        winSound.volume = 0.2;
        winSound.play().catch(e => console.log('No se pudo reproducir el sonido'));
    } else if (type === 'draw') {
        // Sonido de empate
        const drawSound = new Audio('data:audio/wav;base64,UklGRl9vT19XQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YU' + 
            'B'.repeat(500));
        drawSound.volume = 0.2;
        drawSound.play().catch(e => console.log('No se pudo reproducir el sonido'));
    } else if (type === 'move') {
        // Sonido de movimiento
        const moveSound = new Audio('data:audio/wav;base64,UklGRl9vT19XQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YU' + 
            'C'.repeat(200));
        moveSound.volume = 0.2;
        moveSound.play().catch(e => console.log('No se pudo reproducir el sonido'));
    }
}

// Iniciar modo local
function startLocalGame() {
    gameMode = 'local';
    gameSection.classList.remove('hidden');
    onlineOptions.classList.add('hidden');
    updateStatus('🔴 INICIANDO JUEGO LOCAL...');
    setTimeout(() => {
        initGame();
    }, 1000);
}

// Iniciar modo online
function startOnlineGame() {
    gameMode = 'online';
    onlineOptions.classList.remove('hidden');
    gameSection.classList.add('hidden');
    
    // Conectar al servidor Socket.IO
    socket = io();
    
    // Configurar manejadores de eventos del socket
    setupSocketHandlers();
}

// Configurar manejadores de eventos del socket
function setupSocketHandlers() {
    // Error de conexión
    socket.on('connect_error', (error) => {
        console.error('Error de conexión:', error);
        statusDisplay.textContent = 'Error de conexión al servidor';
    });
    
    // Unirse a una sala
    socket.on('roomJoined', (data) => {
        roomId = data.room;
        playerSymbol = data.symbol;
        gameSection.classList.remove('hidden');
        updateStatus(`🌐 SALA: ${roomId}\nTÚ ERES: ${playerSymbol}`);
        setTimeout(() => {
            initGame();
        }, 1500);
    });
    
    // Actualizar el juego cuando el oponente hace un movimiento
    socket.on('gameUpdate', (data) => {
        const { index, symbol } = data;
        gameState[index] = symbol;
        cells[index].textContent = symbol;
        cells[index].classList.add(symbol.toLowerCase());
        playSound('move');
        checkResult();
    });
    
    // Notificación de jugador desconectado
    socket.on('playerDisconnected', () => {
        gameActive = false;
        statusDisplay.textContent = 'El oponente se ha desconectado';
    });
}

// Crear una sala
function createRoom() {
    if (socket) {
        socket.emit('createRoom');
    }
}

// Unirse a una sala existente
function joinRoom() {
    const room = roomIdInput.value.trim();
    if (socket && room) {
        socket.emit('joinRoom', { room });
    } else {
        statusDisplay.textContent = 'Por favor ingresa un ID de sala válido';
    }
}

// Event Listeners
localModeBtn.addEventListener('click', startLocalGame);
onlineModeBtn.addEventListener('click', startOnlineGame);
createRoomBtn.addEventListener('click', createRoom);
joinRoomBtn.addEventListener('click', joinRoom);
resetBtn.addEventListener('click', initGame);

// Añadir manejadores de eventos a las celdas
cells.forEach(cell => {
    cell.addEventListener('click', handleCellClick);
});

// Inicializar el juego
initGame();
