package main

import (
        "secure_application/ip_detector"
        "net/http"
)

func main() {
        http.HandleFunc("/", ip_detector.HandlePostCall)
        http.ListenAndServe(":8080", nil)
}
