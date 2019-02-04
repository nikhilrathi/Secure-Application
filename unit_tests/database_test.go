package unit_tests

import (
        "testing"
        "ip_detector"
)


func TestInformation(t *testing.T) {
        test_pd := ip_detector.Post_data{}
        test_pd.Username = "nick"
        test_pd.UnixTimeStamp = 1234567
        test_pd.EventId = "abcd-yp-op"
        test_pd.IpAddress = "gdfkafa"
        err := ip_detector.Store_in_database(test_pd)
        if err != nil {
            t.Errorf(err.Error())
        }
}

func TestIpInformation(t *testing.T) {
        _, err := ip_detector.Find_ip_information("67.59.59.44")
        if err != nil {
            t.Errorf(err.Error())
        }
}

