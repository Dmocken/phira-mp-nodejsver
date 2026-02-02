
document.addEventListener('DOMContentLoaded', () => {
    const playerListDiv = document.getElementById('all-players-list');

    async function fetchAllPlayers() {
        try {
            const response = await fetch('/api/all-players');
            if (response.status === 403) {
                playerListDiv.innerHTML = '<p>Access Denied. You must be an admin to view this page. <a href="/admin">Login</a></p>';
                return;
            }
            if (!response.ok) {
                throw new Error(`Failed to fetch players: ${response.statusText}`);
            }
            const players = await response.json();
            renderPlayers(players);
        } catch (error) {
            console.error('Error fetching all players:', error);
            playerListDiv.innerHTML = `<p>Error loading players: ${error.message}</p>`;
        }
    }

    function renderPlayers(players) {
        if (!players || players.length === 0) {
            playerListDiv.innerHTML = '<p>No players are currently online.</p>';
            return;
        }

        const playerListHtml = players.map(p => {
            const locationHtml = p.roomId 
                ? `In Room: <a href="room.html?id=${p.roomId}">${p.roomName}</a>`
                : 'In Lobby';
            
            return `
            <li class="player-item">
                <div>
                    <a class="player-name" href="https://phira.moe/user/${p.id}" target="_blank">${p.name} (ID: ${p.id})</a>
                </div>
                <span>${locationHtml}</span>
            </li>
            `;
        }).join('');

        playerListDiv.innerHTML = `
            <h3>All Online Players (${players.length})</h3>
            <ul class="player-list">
                ${playerListHtml}
            </ul>
        `;
    }

    fetchAllPlayers();
});
