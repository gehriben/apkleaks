import requests


class EndpointValidation():
    def __init__(self):
        pass
    
    def search_for_valid_endpoint(self, secret):
        return self.do_google_maps_requests(secret)

    def do_google_maps_requests(self, secret):
        responses = dict()
        valid_apis = list()
        not_authorized_response = False
        base_url = "https://maps.googleapis.com/maps/api"

        # Places API
        url = base_url+"/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=formatted_address%2Cname%2Crating%2Copening_hours%2Cgeometry&key="+secret
        responses['PlacesAPI'] = requests.request("GET", url).text

        # Directions API
        url = base_url+"/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood&key="+secret
        responses['DirectionsAPI'] = requests.request("GET", url).text

        # Geocode API
        url = base_url+"/geocode/json?address=1600+Amphitheatre+Parkway,+Mountain+View,+CA&key="+secret
        responses['GeocodeAPI'] = requests.request("GET", url).text

        # Static Maps API
        url = base_url+"/staticmap?center=Brooklyn+Bridge,New+York,NY&zoom=13&size=600x300&maptype=roadmap&markers=color:blue%7Clabel:S%7C40.702147,-74.015794&markers=color:green%7Clabel:G%7C40.711614,-74.012318&markers=color:red%7Clabel:C%7C40.718217,-73.998284&key="+secret+"&signature=YOUR_SIGNATURE"
        responses['StaticMapsAPI'] = requests.request("GET", url).text

        # Static StreetView API
        url = base_url+"/streetview?size=400x400&location=47.5763831,-122.4211769&fov=80&heading=70&pitch=0&key="+secret+"&signature=YOUR_SIGNATURE"
        responses['StaticStreetViewAPI'] = requests.request("GET", url).text

        # Roads API
        url = "https://roads.googleapis.com/v1/snapToRoads?parameters&key=YOUR_API_KEY"+secret
        responses['RoadsAPI'] = requests.request("GET", url).text

        # Geolocation API
        url = base_url+"geolocation/v1/geolocate?key="+secret
        responses['GeolocationAPI'] = requests.request("POST", url).text

        for api_name, response in responses.items():
            if not 'The provided API key is invalid' in response and not 'API key not valid' in response and not 'This API project is not authorized to use this API' in response:
                valid_apis.append(api_name)
            elif "This API project is not authorized to use this API" in response:
                not_authorized_response = True 

        
        if valid_apis:
            return valid_apis
        elif not_authorized_response:
            return 'Api key is valid but the specific endpoint couldnt be found'
        else:
            return 'No valid api endpoint found!'
        
