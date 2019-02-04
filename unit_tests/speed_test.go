package unit_tests

import (
        "testing"
        "ip_detector"
)


func TestCalculateSpeed(t *testing.T) {
        speed := ip_detector.Calculate_speed(36,2,12)
        var test_speed float64
        test_speed = 1.0
        if speed != test_speed {
            t.Errorf("Speed was incorrect: received %f instead of %f", speed, test_speed)
        }
}

func TestCalculateDistance(t *testing.T) {
        distance := ip_detector.Calculate_distance(30.3764, -97.7078, 30.3764, -97.7078)
        
        if distance != 0.0 {
            t.Errorf("Error in calculating distance: received %f instead of %f", distance, 0.0)
        }
}