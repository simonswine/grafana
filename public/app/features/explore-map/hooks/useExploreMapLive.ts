import { useEffect, useRef, useCallback } from 'react';
import { useDispatch, useSelector } from 'react-redux';

import { LiveChannelScope } from '@grafana/data';
import { getGrafanaLiveSrv } from '@grafana/runtime';

import { updateCursor, removeCursor } from '../state/exploreMapSlice';
import { selectMapUid } from '../state/selectors';
import { getOrCreateSessionId } from '../utils/sessionId';

interface CursorUpdateMessage {
  type: 'cursor_update';
  sessionId: string;
  userId: string;
  userName: string;
  timestamp: number;
  data: {
    x: number;
    y: number;
    color: string;
    panelId?: string;
  };
}

interface CursorLeaveMessage {
  type: 'cursor_leave';
  sessionId: string;
}

type ExploreMapMessage = CursorUpdateMessage | CursorLeaveMessage;

const CURSOR_UPDATE_THROTTLE_MS = 50; // Limit to ~20 updates/sec

interface UseExploreMapLiveOptions {
  currentUserId: string;
  currentUserName: string;
  enabled?: boolean;
}

export function useExploreMapLive({ currentUserId, currentUserName, enabled = true }: UseExploreMapLiveOptions) {
  const dispatch = useDispatch();
  const mapUid = useSelector(selectMapUid);
  const subscriptionRef = useRef<any>(null);
  const lastPublishRef = useRef<number>(0);
  const pendingUpdateRef = useRef<any>(null);
  const throttleTimeoutRef = useRef<NodeJS.Timeout>();
  const sessionIdRef = useRef<string>(getOrCreateSessionId());

  // Subscribe to channel
  useEffect(() => {
    if (!mapUid || !enabled) {
      return;
    }

    const liveSrv = getGrafanaLiveSrv();
    if (!liveSrv) {
      console.warn('Grafana Live not available');
      return;
    }

    const channelAddress = {
      scope: LiveChannelScope.Grafana,
      namespace: 'explore-map',
      path: `uid/${mapUid}`,
    };

    console.log('ExploreMap: Subscribing to channel', channelAddress);

    // Subscribe to channel
    const channel = liveSrv.getStream(channelAddress);

    const subscription = channel.subscribe({
      next: (event) => {
        console.log('ExploreMap: Received event', event);

        if (event.type === 'message') {
          handleIncomingMessage(event.message);
        } else if (event.type === 'leave') {
          // User left the channel
          console.log('ExploreMap: User left', event.user);
          if (event.user) {
            dispatch(removeCursor({ userId: event.user }));
          }
        } else if (event.type === 'join') {
          console.log('ExploreMap: User joined', event.user);
        }
      },
      error: (err) => {
        console.error('ExploreMap Live error:', err);
      },
    });

    subscriptionRef.current = subscription;

    return () => {
      console.log('ExploreMap: Unsubscribing from channel');
      subscription.unsubscribe();
      if (throttleTimeoutRef.current) {
        clearTimeout(throttleTimeoutRef.current);
      }
    };
  }, [mapUid, enabled, dispatch, currentUserId]);

  // Handle incoming messages
  const handleIncomingMessage = useCallback(
    (data: any) => {
      try {
        const message: ExploreMapMessage = typeof data === 'string' ? JSON.parse(data) : data;

        console.log('ExploreMap: Received message', {
          messageSessionId: message.sessionId,
          mySessionId: sessionIdRef.current,
          isSameSession: message.sessionId === sessionIdRef.current,
          message,
        });

        // Ignore own messages from this session (already in local state)
        if (message.sessionId === sessionIdRef.current) {
          console.log('ExploreMap: Ignoring own message (same sessionId)');
          return;
        }

        console.log('ExploreMap: Processing message from different session');

        switch (message.type) {
          case 'cursor_update':
            dispatch(
              updateCursor({
                userId: message.sessionId, // Use sessionId as the unique identifier
                userName: `${message.userName} (${message.sessionId.split('-')[1]?.substring(0, 4)})`, // Show user + session hint
                color: message.data.color,
                x: message.data.x,
                y: message.data.y,
                lastUpdated: message.timestamp,
              })
            );
            break;

          case 'cursor_leave':
            dispatch(removeCursor({ userId: message.sessionId })); // Use sessionId
            break;

          default:
            console.warn('ExploreMap: Unknown message type', message);
        }
      } catch (err) {
        console.error('Failed to parse ExploreMap message:', err);
      }
    },
    [dispatch]
  );

  // Publish cursor update (throttled)
  const publishCursorUpdate = useCallback(
    (x: number, y: number, color: string, panelId?: string) => {
      if (!mapUid || !enabled) {
        return;
      }

      const now = Date.now();
      const timeSinceLastPublish = now - lastPublishRef.current;

      // Store the pending update
      pendingUpdateRef.current = { x, y, color, panelId };

      // If enough time has passed, publish immediately
      if (timeSinceLastPublish >= CURSOR_UPDATE_THROTTLE_MS) {
        publishNow();
      } else if (!throttleTimeoutRef.current) {
        // Schedule a publish for later
        const delay = CURSOR_UPDATE_THROTTLE_MS - timeSinceLastPublish;
        throttleTimeoutRef.current = setTimeout(() => {
          publishNow();
          throttleTimeoutRef.current = undefined;
        }, delay);
      }
    },
    [mapUid, enabled]
  );

  const publishNow = useCallback(() => {
    if (!pendingUpdateRef.current || !mapUid) {
      return;
    }

    const { x, y, color, panelId } = pendingUpdateRef.current;

    const message = {
      type: 'cursor_update' as const,
      sessionId: sessionIdRef.current,
      data: { x, y, color, panelId },
    };

    const liveSrv = getGrafanaLiveSrv();
    if (!liveSrv) {
      return;
    }

    console.log('ExploreMap: Publishing cursor update', message);

    // Publish to channel
    const publishAddress = {
      scope: LiveChannelScope.Grafana,
      namespace: 'explore-map',
      path: `uid/${mapUid}`,
    };

    liveSrv
      .publish(publishAddress, message)
      .catch((err) => {
        console.error('Failed to publish cursor update:', err);
      });

    lastPublishRef.current = Date.now();
    pendingUpdateRef.current = null;
  }, [mapUid]);

  // Notify when leaving
  const publishLeave = useCallback(() => {
    if (!mapUid || !enabled) {
      return;
    }

    const message = {
      type: 'cursor_leave' as const,
      sessionId: sessionIdRef.current,
    };

    const liveSrv = getGrafanaLiveSrv();
    if (!liveSrv) {
      return;
    }

    console.log('ExploreMap: Publishing leave event');

    const publishAddress = {
      scope: LiveChannelScope.Grafana,
      namespace: 'explore-map',
      path: `uid/${mapUid}`,
    };

    liveSrv
      .publish(publishAddress, message)
      .catch((err) => {
        console.error('Failed to publish leave event:', err);
      });
  }, [mapUid, enabled]);

  return {
    publishCursorUpdate,
    publishLeave,
    isConnected: !!subscriptionRef.current,
  };
}
