var keyStore = Reflux.createStore({
    fetchKey: function(url) {
        // Assume `request` is some HTTP library (e.g. superagent)
        request(url, function(response) {
            if (response.ok) {
                makeRequest.completed(response.body);
            } else {
                makeRequest.failed(response.error);
            }
        })
    }
});
