
document.addEventListener('DOMContentLoaded', () => {
    const roomName = document.getElementById('room-name');
    const roomDetails = document.getElementById('room-details');
    const connectionStatus = document.getElementById('connection-status');
    
    const params = new URLSearchParams(window.location.search);
    const roomId = params.get('id');
    let socket;

    if (!roomId) {
        roomName.textContent = 'Error: No Room ID specified';
        return;
    }

    function connectWebSocket() {
        const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${wsProtocol}//${window.location.host}`;

        socket = new WebSocket(wsUrl);

        socket.onopen = () => {
            console.log('WebSocket connection established for room details');
            connectionStatus.textContent = 'Connected';
            connectionStatus.className = 'connection-status connected';

            // Request details for the specific room
            const message = {
                type: 'getRoomDetails',
                payload: { roomId: roomId }
            };
            socket.send(JSON.stringify(message));
        };

        socket.onmessage = (event) => {
            try {
                const message = JSON.parse(event.data);
                if (message.type === 'roomDetails') {
                    console.log('Received room details:', message.payload);
                    renderRoomDetails(message.payload);
                }
                // The main list update can also trigger a re-fetch for simplicity
                if (message.type === 'roomList') {
                     const message = {
                        type: 'getRoomDetails',
                        payload: { roomId: roomId }
                    };
                    socket.send(JSON.stringify(message));
                }
            } catch (error) {
                console.error('Error parsing room data:', error);
            }
        };

        socket.onclose = () => {
            console.log('WebSocket connection closed. Reconnecting in 3 seconds...');
            connectionStatus.textContent = 'Disconnected';
            connectionStatus.className = 'connection-status disconnected';
            setTimeout(connectWebSocket, 3000);
        };

        socket.onerror = (error) => {
            console.error('WebSocket error:', error);
        };
    }

    function renderRoomDetails(details) {
        if (!details) {
            roomName.textContent = `Error: Room "${roomId}" not found`;
            roomDetails.innerHTML = '';
            return;
        }

        roomName.textContent = `Room: ${details.name}`;

        const lockIcon = details.locked ? '&#128274;' : '&#128275;';
        const lockStatusClass = details.locked ? 'locked-status' : 'unlocked-status';

        const chartName = details.selectedChart ? details.selectedChart.name : 'Not selected';
        const chartLevel = details.selectedChart ? details.selectedChart.level : 'N/A';
        const chartId = details.selectedChart ? details.selectedChart.id : 'N/A';
        const chartLink = details.selectedChart ? `<a href="https://phira.moe/chart/${details.selectedChart.id}" target="_blank">${details.selectedChart.id}</a>` : 'N/A';

        const playersHtml = details.players.map(p => `
            <li class="player-item ${p.id === details.ownerId ? 'owner' : ''} ${p.isReady ? 'ready' : ''}">
                <div class="player-info-left">
                    <span class="player-icon">${p.id === details.ownerId ? '&#128081;' : ''}</span>
                    <a class="player-name" href="https://phira.moe/user/${p.id}" target="_blank">${p.name} (ID: ${p.id})</a>
                </div>
                <span class="player-status">${p.isReady ? 'Ready' : 'Not Ready'}</span>
            </li>
        `).join('');

        roomDetails.innerHTML = `
            <div class="detail-card">
                <h3>Room Info</h3>
                <p><strong>ID:</strong> ${details.id}</p>
                <p><strong>Players:</strong> ${details.playerCount} / ${details.maxPlayers}</p>
                <p><strong>Status:</strong> ${details.state.type}</p>
                <p><strong>Locked:</strong> <span class="${lockStatusClass}">${lockIcon}</span></p>
            </div>
            <div class="detail-card">
                <h3>Chart</h3>
                <p><strong>Name:</strong> ${chartName}</p>
                <p><strong>ID:</strong> ${chartLink}</p>
                <p><strong>Level:</strong> ${chartLevel}</p>
            </div>
            <div class="detail-card full-width">
                <h3>Player List</h3>
                <ul class="player-list">
                    ${playersHtml}
                </ul>
            </div>
        `;
    }

    connectWebSocket();
});
