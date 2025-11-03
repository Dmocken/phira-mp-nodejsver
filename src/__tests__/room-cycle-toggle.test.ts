/*
 * MIT License
 * Copyright (c) 2024
 */

import { ProtocolHandler } from '../domain/protocol/ProtocolHandler';
import { InMemoryRoomManager } from '../domain/rooms/RoomManager';
import { AuthService } from '../domain/auth/AuthService';
import { Logger } from '../logging/logger';
import { ClientCommandType, ServerCommandType } from '../domain/protocol/Commands';

const mockLogger: Logger = {
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn(),
};

const mockAuthService: AuthService = {
  authenticate: jest.fn(),
};

describe('Room cycle toggle', () => {
  let protocolHandler: ProtocolHandler;
  let roomManager: InMemoryRoomManager;
  let mockSendResponse: jest.Mock;

  beforeEach(() => {
    roomManager = new InMemoryRoomManager(mockLogger);
    protocolHandler = new ProtocolHandler(roomManager, mockAuthService, mockLogger);
    mockSendResponse = jest.fn();
  });

  it('should allow room owner to toggle cycle mode on and off', () => {
    const connectionId = 'conn-1';
    const userId = 1;
    const roomId = 'room-1';

    // Seed session
    (protocolHandler as any).sessions.set(connectionId, {
      userId,
      userInfo: { id: userId, name: 'Owner', monitor: false },
      connectionId,
    });

    // Create room
    roomManager.createRoom({
      id: roomId,
      name: roomId,
      ownerId: userId,
      ownerInfo: { id: userId, name: 'Owner', monitor: false },
      connectionId,
    });

    const room = roomManager.getRoom(roomId);
    expect(room).not.toBeUndefined();
    if (!room) {
      throw new Error('Room not created');
    }

    // Initially cycle should be false
    expect(room.cycle).toBe(false);

    // Register broadcast callback
    (protocolHandler as any).broadcastCallbacks.set(connectionId, mockSendResponse);

    // Toggle cycle on
    protocolHandler.handleMessage(
      connectionId,
      {
        type: ClientCommandType.CycleRoom,
        cycle: true,
      },
      mockSendResponse,
    );

    // Should succeed
    const successCall = mockSendResponse.mock.calls.find(
      (call) => call[0].type === ServerCommandType.CycleRoom,
    );
    expect(successCall).toBeDefined();
    expect(successCall?.[0]).toEqual(
      expect.objectContaining({
        type: ServerCommandType.CycleRoom,
        result: { ok: true, value: undefined },
      }),
    );

    // Room cycle should be true
    expect(room.cycle).toBe(true);

    // Clear mock
    mockSendResponse.mockClear();

    // Toggle cycle off
    protocolHandler.handleMessage(
      connectionId,
      {
        type: ClientCommandType.CycleRoom,
        cycle: false,
      },
      mockSendResponse,
    );

    // Should succeed
    const successCall2 = mockSendResponse.mock.calls.find(
      (call) => call[0].type === ServerCommandType.CycleRoom,
    );
    expect(successCall2).toBeDefined();
    expect(successCall2?.[0]).toEqual(
      expect.objectContaining({
        type: ServerCommandType.CycleRoom,
        result: { ok: true, value: undefined },
      }),
    );

    // Room cycle should be false again
    expect(room.cycle).toBe(false);
  });

  it('should reject cycle toggle from non-owner', () => {
    const ownerConnection = 'conn-owner';
    const guestConnection = 'conn-guest';
    const ownerId = 1;
    const guestId = 2;
    const roomId = 'room-1';

    // Seed sessions
    (protocolHandler as any).sessions.set(ownerConnection, {
      userId: ownerId,
      userInfo: { id: ownerId, name: 'Owner', monitor: false },
      connectionId: ownerConnection,
    });

    (protocolHandler as any).sessions.set(guestConnection, {
      userId: guestId,
      userInfo: { id: guestId, name: 'Guest', monitor: false },
      connectionId: guestConnection,
    });

    // Create room
    roomManager.createRoom({
      id: roomId,
      name: roomId,
      ownerId: ownerId,
      ownerInfo: { id: ownerId, name: 'Owner', monitor: false },
      connectionId: ownerConnection,
    });

    roomManager.addPlayerToRoom(roomId, guestId, { id: guestId, name: 'Guest', monitor: false }, guestConnection);

    const room = roomManager.getRoom(roomId);
    expect(room).not.toBeUndefined();
    if (!room) {
      throw new Error('Room not created');
    }

    // Initially cycle should be false
    expect(room.cycle).toBe(false);

    // Register broadcast callback for guest
    (protocolHandler as any).broadcastCallbacks.set(guestConnection, mockSendResponse);

    // Guest tries to toggle cycle
    protocolHandler.handleMessage(
      guestConnection,
      {
        type: ClientCommandType.CycleRoom,
        cycle: true,
      },
      mockSendResponse,
    );

    // Should fail
    const errorCall = mockSendResponse.mock.calls.find(
      (call) => call[0].type === ServerCommandType.CycleRoom,
    );
    expect(errorCall).toBeDefined();
    expect(errorCall?.[0]).toEqual(
      expect.objectContaining({
        type: ServerCommandType.CycleRoom,
        result: { ok: false, error: 'baka!你不是房主喵' },
      }),
    );

    // Room cycle should still be false
    expect(room.cycle).toBe(false);
  });

  it('should broadcast cycle change to all room members', () => {
    const ownerConnection = 'conn-owner';
    const guestConnection = 'conn-guest';
    const ownerId = 1;
    const guestId = 2;
    const roomId = 'room-1';

    // Seed sessions
    (protocolHandler as any).sessions.set(ownerConnection, {
      userId: ownerId,
      userInfo: { id: ownerId, name: 'Owner', monitor: false },
      connectionId: ownerConnection,
    });

    (protocolHandler as any).sessions.set(guestConnection, {
      userId: guestId,
      userInfo: { id: guestId, name: 'Guest', monitor: false },
      connectionId: guestConnection,
    });

    // Create room and add guest
    roomManager.createRoom({
      id: roomId,
      name: roomId,
      ownerId: ownerId,
      ownerInfo: { id: ownerId, name: 'Owner', monitor: false },
      connectionId: ownerConnection,
    });

    roomManager.addPlayerToRoom(roomId, guestId, { id: guestId, name: 'Guest', monitor: false }, guestConnection);

    const room = roomManager.getRoom(roomId);
    expect(room).not.toBeUndefined();
    if (!room) {
      throw new Error('Room not created');
    }

    const mockOwnerSendResponse = jest.fn();
    const mockGuestSendResponse = jest.fn();

    // Register broadcast callbacks
    (protocolHandler as any).broadcastCallbacks.set(ownerConnection, mockOwnerSendResponse);
    (protocolHandler as any).broadcastCallbacks.set(guestConnection, mockGuestSendResponse);

    // Owner toggles cycle
    protocolHandler.handleMessage(
      ownerConnection,
      {
        type: ClientCommandType.CycleRoom,
        cycle: true,
      },
      mockOwnerSendResponse,
    );

    // Both owner and guest should receive the message
    const ownerMessageCall = mockOwnerSendResponse.mock.calls.find(
      (call) => call[0].type === ServerCommandType.Message,
    );
    const guestMessageCall = mockGuestSendResponse.mock.calls.find(
      (call) => call[0].type === ServerCommandType.Message,
    );

    expect(ownerMessageCall).toBeDefined();
    expect(guestMessageCall).toBeDefined();
    
    expect(ownerMessageCall?.[0].message).toEqual(
      expect.objectContaining({
        type: 'CycleRoom',
        cycle: true,
      })
    );
    
    expect(guestMessageCall?.[0].message).toEqual(
      expect.objectContaining({
        type: 'CycleRoom',
        cycle: true,
      })
    );
  });
});