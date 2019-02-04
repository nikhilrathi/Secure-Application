package ip_detector

import (
        "fmt"
        "net/http"
        "net"
        "math"
        "encoding/json"
        "io/ioutil"
        "database/sql"
        "time"
        "sort"
        "github.com/oschwald/geoip2-golang"
        _ "github.com/mattn/go-sqlite3"
        
)

type Post_data struct {
        Username string `json:"username"`
        UnixTimeStamp float64 `json:"unix_timestamp"`
        EventId string `json:"event_uuid"`
        IpAddress string `json:"ip_address"`
}

type Geo struct {
        Lat float64 `json:"lat"`
        Lon float64 `json:"lon"`
        Radius uint16 `json:"radius"`
}

type IpAccess struct {
        Ip string `json:"ip"`
        Speed float64 `json:"speed"`
        Lat float64 `json:"lat"`
        Lon float64 `json:"lon"`
        Radius uint16 `json:"radius"`
        TimeStamp float64 `json:"timestamp"`
}

type Response_data struct {
        CurrentGeo Geo `json:"currentGeo"`
        TravelToCurrentGeoSuspicious bool `json:"travelToCurrentGeoSuspicious"`
        TravelFromCurrentGeoSuspicious bool `json:"travelFromCurrentGeoSuspicious"`
        PrecedingIpAccess IpAccess `json:"precedingIpAccess"`
        SubsequentIpAccess IpAccess `json:"subsequentIpAccess"`
}

// Gather the post information and store it in database
func Store_in_database(pd Post_data) error{
        //Connect to database
        db, err := sql.Open("sqlite3", "./secure_ip_detector.db")
        if err != nil {
            fmt.Println("Error in opening secure ip detector sql database")
            return err
        }
        
        // Insert the information into database
        stmt, err := db.Prepare("Insert INTO logins(username, unix_timestamp, event_uuid, ip_address) values(?,?,?,?)")
        if err != nil {
            fmt.Println("Error in preparing insert statement")
            return err
        }
        _, err = stmt.Exec(pd.Username, pd.UnixTimeStamp, pd.EventId, pd.IpAddress)
        if err != nil {
            fmt.Println("Error in executing insert statement", err)
            return err
        }
        
        // Close the database
        defer db.Close()
        
        fmt.Println("Stored information for", pd.Username)
        return nil
}

// Gather the ip information given a ip_address
func Find_ip_information(ip_address string) (Geo, error) {
        current_geo_information := Geo{}
        
        // Connect to the geoip2 database
        db, err := geoip2.Open("GeoLite2-City_20190122/GeoLite2-City.mmdb")
        if err != nil {
            fmt.Println("Error in opening the db for ip look up")
            return current_geo_information, err
        }
        
        defer db.Close()
        
        // Find ip information from the database city map
        ip := net.ParseIP(ip_address)
        record, err := db.City(ip)
        if err != nil {
            fmt.Println("Ip check failed!")
            return current_geo_information, err
        }
        
        current_geo_information.Lat = record.Location.Latitude
        current_geo_information.Lon = record.Location.Longitude
        current_geo_information.Radius = record.Location.AccuracyRadius
        
        // Return the ip information collected
        return current_geo_information, nil
}

// Calculate the distance using the Havershine formula
func Calculate_distance(lat1, lon1, lat2, lon2 float64) float64 {
        var distance float64
        diff_lat := lat2-lat1
        diff_lon := lon2-lon1
        sin_square_lat := math.Sin(diff_lat/2)*math.Sin(diff_lat/2)
        sin_square_lon := math.Sin(diff_lon/2)*math.Sin(diff_lon/2)
        r := 6.371*1000000
        
        distance = 2*r*math.Asin(math.Sqrt(sin_square_lat+(sin_square_lon*math.Cos(lat1)*math.Cos(lat2))))
        
        return distance
}

// Calculate the speed in kmph
func Calculate_speed(distance, time1, time2 float64) float64 {
        var speed float64
        speed = distance/(time2-time1)/3.6
        return speed
}

// Generate the output object by finding the nearest time stamp entries of a user
func Generate_output_json(pd Post_data, user_logins []Post_data) (Response_data, error){
        output := Response_data{}
        
        // Get the lat, lon, radius from given ip
        current_geo_information, err := Find_ip_information(pd.IpAddress)
        if err != nil {
            return output, err
        }
        
        output.CurrentGeo = current_geo_information
        
        if len(user_logins) != 0 {
            // Sort all the user entries
            sort.Slice(user_logins, func(i,j int) bool {
                return user_logins[i].UnixTimeStamp < user_logins[j].UnixTimeStamp
            })
            
            // Find the previous and next entries 
            pre, next := Find_nearest(user_logins, pd.UnixTimeStamp)
            
            // Populate the previous entry information if exists
            if pre.Username != "" {
                pre_ip := IpAccess{}
                pre_geo_information, err := Find_ip_information(pre.IpAddress)
                if err != nil {
                    return output, err
                }
                pre_ip.Ip = pre.IpAddress
                pre_ip.TimeStamp = pre.UnixTimeStamp
                pre_ip.Lat = pre_geo_information.Lat
                pre_ip.Lon = pre_geo_information.Lon
                pre_ip.Radius = uint16(pre_geo_information.Radius)
                distance := Calculate_distance(pre_ip.Lat, pre_ip.Lon, current_geo_information.Lat, current_geo_information.Lon)
                pre_ip.Speed = Calculate_speed(distance, pre_ip.TimeStamp, pd.UnixTimeStamp)
                output.PrecedingIpAccess = pre_ip
                if pre_ip.Speed > 500 {
                    output.TravelToCurrentGeoSuspicious = true
                }
            }
            
            // Populate the next entry information if exists
            if next.Username != "" {
                next_ip := IpAccess{}
                next_geo_information, err := Find_ip_information(next.IpAddress)
                if err != nil {
                    return output, err
                }
                next_ip.Ip = next.IpAddress
                next_ip.TimeStamp = next.UnixTimeStamp
                next_ip.Lat = next_geo_information.Lat
                next_ip.Lon = next_geo_information.Lon
                next_ip.Radius = uint16(next_geo_information.Radius)
                distance := Calculate_distance(current_geo_information.Lat, current_geo_information.Lon, next_ip.Lat, next_ip.Lon)
                next_ip.Speed = Calculate_speed(distance, pd.UnixTimeStamp, next_ip.TimeStamp)
                output.SubsequentIpAccess = next_ip
                if next_ip.Speed > 500 {
                    output.TravelFromCurrentGeoSuspicious = true
                }
            }
        }
        
        // Store the current information in database
        err = Store_in_database(pd)
        
        if err != nil {
            return output, err
        }
        
        return output, nil
}

// Find the nearest neighbors of a timestamp in user login entries
func Find_nearest(logins []Post_data, target float64) (Post_data, Post_data) {
        n := len(logins)
        if target < logins[0].UnixTimeStamp {
            return Post_data{}, logins[0]
        } else {
            for i:=1; i < n; i++ {
                if (target > logins[i-1].UnixTimeStamp && target < logins[i].UnixTimeStamp){
                    return logins[i-1], logins[i]
                }
            }
        }
        return logins[n-1], Post_data{}
}

// Connect to database and get information regarding a users previous entries
func Get_user_information(pd Post_data) ([]Post_data, error) {
        // Connect to database
        db, err := sql.Open("sqlite3", "./secure_ip_detector.db")
        if err != nil {
            fmt.Println("Error in opening secure ip detector sql database")
            return []Post_data{}, err
        }
        
        // Query for the particular user information
        query := fmt.Sprintf("SELECT * FROM logins WHERE username = '%s'", pd.Username)
        rows, err := db.Query(query)
        if err != nil {
            fmt.Println("Error in querying for a particular user")
            return []Post_data{}, err
        }
        
        // Close the db
        defer db.Close()
        
        var username string
        var timestamp time.Time
        var ip_address string
        var event_uuid string
        
        var user_logins = []Post_data{}
        for rows.Next() {
            err = rows.Scan(&username, &timestamp, &event_uuid, &ip_address)
            user_logins = append(user_logins, Post_data{username, float64(timestamp.Unix()), event_uuid, ip_address})
        }
        
        // Return queried user information
        return user_logins, nil
}

// Function to handle a host call at port 8080
func HandlePostCall(w http.ResponseWriter, r *http.Request) {
        pd := Post_data{}
        
        // Read the post call body - if any error in body send http error
        jsn, err := ioutil.ReadAll(r.Body)
        if err != nil {
            http.Error(w, "Error in post body", 400)
            return
        }
        
        // Read the json and unmarshal - if any error in decoding send http error
        err = json.Unmarshal(jsn, &pd)
        if err != nil {
            http.Error(w, "Error in decoding the json post content", 400)
            return
        }
        
        // Validate the user sent post data (check if the fields are populated)
        if pd.Username == "" {
            http.Error(w, "Error in reading username", 400)
            return
        }
        if pd.UnixTimeStamp == 0 {
            http.Error(w, "Error in reading unix_timestamp", 400)
            return
        }
        if pd.EventId == "" {
            http.Error(w, "Error in reading event_uuid", 400)
            return
        }
        if pd.IpAddress == "" {
            http.Error(w, "Error in reading ip_address", 400)
            return
        }
        
        // Get the user information
        user_information, err := Get_user_information(pd)
        if err != nil {
            http.Error(w, err.Error(), 400)
            return
        }
        
        // Get the output json object and send it back to the call handle method to write back
        output_json, err := Generate_output_json(pd, user_information)
        
        if err != nil {
            http.Error(w, err.Error(), 400)
            return
        }
        
        Make_output_neat_and_write_back(output_json, w)
        
        
}

// Clean the output and write it back to the http call
func Make_output_neat_and_write_back(output Response_data, w http.ResponseWriter){
        // Set the content type to application/json
        w.Header().Set("Content-Type", "application/json")
        
        // If no preceeding and subsequent information is present 
        // then just output the current geo information
        if output.PrecedingIpAccess.Ip == "" && output.SubsequentIpAccess.Ip == "" {
            return_jsn  := struct{
                CurrentGeo Geo `json:"currentGeo"`
            }{
                CurrentGeo: Geo {
                    Lat: output.CurrentGeo.Lat,
                    Lon: output.CurrentGeo.Lon,
                    Radius: output.CurrentGeo.Radius,
                },
            }
            response_jsn, err := json.MarshalIndent(return_jsn, "", "    ")
            if err != nil {
                fmt.Println("Error in converting response to json")
            }
            w.Write(response_jsn)
            return
        }
        
        // If only Preceeding information is present then 
        // output current geo information and preceeding ip information
        if output.PrecedingIpAccess.Ip == "" {
            return_jsn  := struct{
                CurrentGeo Geo `json:"currentGeo"`
                TravelFromCurrentGeoSuspicious bool `json:"travelFromCurrentGeoSuspicious"`
                SubsequentIpAccess IpAccess `json:"subsequentIpAccess"`
            }{
                CurrentGeo: Geo {
                    Lat: output.CurrentGeo.Lat,
                    Lon: output.CurrentGeo.Lon,
                    Radius: output.CurrentGeo.Radius,
                },
                TravelFromCurrentGeoSuspicious: output.TravelFromCurrentGeoSuspicious,
                SubsequentIpAccess: IpAccess{
                    Ip: output.SubsequentIpAccess.Ip,
                    Speed: output.SubsequentIpAccess.Speed,
                    Lat: output.SubsequentIpAccess.Lat,
                    Lon: output.SubsequentIpAccess.Lon,
                    Radius: output.SubsequentIpAccess.Radius,
                    TimeStamp: output.SubsequentIpAccess.TimeStamp,
                },
            }
            response_jsn, err := json.MarshalIndent(return_jsn, "", "    ")
            if err != nil {
                fmt.Println("Error in converting output to json")
            }
            w.Write(response_jsn)
            return
        }
        
        // If only Subsequent information is present then 
        // output current geo information and subsequent ip information
        if output.SubsequentIpAccess.Ip == "" {
            return_jsn := struct{
                CurrentGeo Geo `json:"currentGeo"`
                TravelToCurrentGeoSuspicious bool `json:"travelToCurrentGeoSuspicious"`
                PrecedingIpAccess IpAccess `json:"preceedingIpAccess"`
            }{
                CurrentGeo: Geo {
                    Lat: output.CurrentGeo.Lat,
                    Lon: output.CurrentGeo.Lon,
                    Radius: output.CurrentGeo.Radius,
                },
                TravelToCurrentGeoSuspicious: output.TravelToCurrentGeoSuspicious,
                PrecedingIpAccess: IpAccess{
                    Ip: output.PrecedingIpAccess.Ip,
                    Speed: output.PrecedingIpAccess.Speed,
                    Lat: output.PrecedingIpAccess.Lat,
                    Lon: output.PrecedingIpAccess.Lon,
                    Radius: output.PrecedingIpAccess.Radius,
                    TimeStamp: output.PrecedingIpAccess.TimeStamp,
                },
            }
            response_jsn, err := json.MarshalIndent(return_jsn, "", "    ")
            if err != nil {
                fmt.Println("Error in converting response to json")
            }
            w.Write(response_jsn)
            return
        }
        
        // If all the data is present then output the complete object in json format
        return_jsn := output
        response_jsn, err := json.MarshalIndent(return_jsn, "", "    ")
        if err != nil {
            fmt.Println("Error in converting response to json")
        }
        w.Write(response_jsn)
        
}
