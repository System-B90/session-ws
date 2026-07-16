"use client";

import { createContext, ReactNode, useContext, useMemo } from "react";

type WebSocketConfigContextType = {
    host: string;
    protocol: string;
    portSuffix: string;
    connectionString: string;
};

const WebSocketConfigContext = createContext<WebSocketConfigContextType>({
    host: "localhost",
    protocol: "wss",
    portSuffix: "",
    connectionString: "wss://localhost/ws/",
});

type WebSocketConfigProviderProps = {
    host: string;
    protocol: string;
    portSuffix: string;
    children: ReactNode;
};

export function WebSocketConfigProvider({
    host,
    protocol,
    portSuffix,
    children,
}: WebSocketConfigProviderProps) {
    const context = useMemo(() => {
        const connectionString = `${protocol}://${host}${portSuffix}/ws/`;
        return { host, protocol, portSuffix, connectionString };
    }, [host, protocol, portSuffix]);

    return (
        <WebSocketConfigContext.Provider value={context}>
            {children}
        </WebSocketConfigContext.Provider>
    );
}

export function useWebSocketConfig() {
    return useContext(WebSocketConfigContext);
}
