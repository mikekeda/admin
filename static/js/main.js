document.addEventListener("DOMContentLoaded", function() {
    let elems = document.querySelectorAll(".dropdown-trigger");
    M.Dropdown.init(elems);
    let tooltips = document.querySelectorAll(".tooltipped");
    M.Tooltip.init(tooltips);
});
