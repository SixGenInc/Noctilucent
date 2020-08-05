package main

import (
	"fmt"
	"log"
	"net/http"

	"golang.org/x/net/websocket"
)

func echoHandler(ws *websocket.Conn) {
	msg := make([]byte, 512)
	n, err := ws.Read(msg)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Receive: %s\n", msg[:n])

	m, err := ws.Write(msg[:n])
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Send: %s\n", msg[:m])
}

func main() {
	http.Handle("/websocket", websocket.Handler(echoHandler))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello DEF CON!")
	})
	err := http.ListenAndServe(":80", nil)
	if err != nil {
		panic("ListenAndServe: " + err.Error())
	}
}
