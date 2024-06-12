// Custom JavaScript for AJAX pagination
document.addEventListener("DOMContentLoaded", function() {
    loadPage(1); // Load the first page of intrusions initially

    function loadPage(pageNumber) {
        // Make an AJAX request to fetch intrusion data for the specified page
        fetch(`/intrusions?page=${pageNumber}`)
            .then(response => response.json())
            .then(data => {
                // Update intrusion data in the table
                document.getElementById("intrusion-data").innerHTML = data.intrusion_html;

                // Update pagination links
                document.getElementById("pagination-links").innerHTML = data.pagination_html;
            })
            .catch(error => console.error("Error loading page:", error));
    }
});
