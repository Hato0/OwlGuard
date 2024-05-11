const menuBar = document.querySelector('.content nav .bx.bx-menu');
const sideBar = document.querySelector('.sidebar');

menuBar.addEventListener('click', () => {
    sideBar.classList.toggle('close');
});

const searchBtn = document.querySelector('.content nav form .form-input button');
const searchBtnIcon = document.querySelector('.content nav form .form-input button .bx');
const searchForm = document.querySelector('.content nav form');

searchBtn.addEventListener('click', function (e) {
    if (window.innerWidth < 576) {
        e.preventDefault;
        searchForm.classList.toggle('show');
        if (searchForm.classList.contains('show')) {
            searchBtnIcon.classList.replace('bx-search', 'bx-x');
        } else {
            searchBtnIcon.classList.replace('bx-x', 'bx-search');
        }
    }
});

window.addEventListener('resize', () => {
    if (window.innerWidth < 768) {
        sideBar.classList.add('close');
    } else {
        sideBar.classList.remove('close');
    }
    if (window.innerWidth > 576) {
        searchBtnIcon.classList.replace('bx-x', 'bx-search');
        searchForm.classList.remove('show');
    }
});

function rowClicked(ruleId) {
// Redirect to a new page with the rule ID
    window.location.href = '/rules/' + ruleId;
}

function rowClickedDocu(docuId) {
// Redirect to a new page with the docu ID
    window.location.href = '/documentation/' + docuId;
}

function rowClickedScript(scriptId) {
// Redirect to a new page with the script ID
    window.location.href = '/script/' + scriptId;
}

function updateFileCount(input) {
    var count = input.files.length;
    var fileCountSpan = document.getElementById("file-count");
    fileCountSpan.textContent = count + (count === 1 ? " file selected" : " files selected");
}

var selectedTags = [];

function filterByTag(tag) {
    if (!selectedTags.includes(tag)) {
        if (selectedTags.length < 3){
            selectedTags.push(tag);
            updateFilterDisplay();
            filterRows();
        }
        else {
            //TODO: alert popup saying 'limited to 3tags'
        }
    }
}

function updateFilterDisplay() {
    var filterInfoDiv = document.querySelector(".filter-info");
    var currentFilterSpan = document.getElementById("currentFilter");
    if (!currentFilterSpan) {
        currentFilterSpan = document.createElement("span");
        currentFilterSpan.id = "currentFilter";
        filterInfoDiv.appendChild(currentFilterSpan);
        filterInfoDiv.insertBefore(document.createTextNode(""), currentFilterSpan);
    } else {
        currentFilterSpan.innerHTML = "";
    }

    var maxTags = Math.min(selectedTags.length, 3);
    for (var i = 0; i < maxTags; i++) {
        var tagAnchor = document.createElement("a");
        tagAnchor.className = "tag";
        tagAnchor.textContent = selectedTags[i];
        tagAnchor.addEventListener("click", (function(index) {
            return function(event) {
                event.preventDefault();
                removeFilter(selectedTags[index]);
            };
        })(i));
        currentFilterSpan.appendChild(tagAnchor);
    }
}

function filterRows() {
    var rows = document.getElementById("rulesTable").getElementsByTagName("tr");
    for (var i = 0; i < rows.length; i++) {
        if (!rows[i].classList.contains("no-rule-info")) {
            var tags = Array.from(rows[i].getElementsByClassName("tag")).map(tag => tag.textContent.trim());
            var displayRow = true; 

            for (var k = 0; k < selectedTags.length; k++) {
                if (!tags.includes(selectedTags[k])) {
                    displayRow = false;
                    break;
                }
            }
            rows[i].style.display = displayRow ? "" : "none";
        }
    }
}

function removeFilter(tag) {
    var index = selectedTags.indexOf(tag);
    if (index !== -1) {
        selectedTags.splice(index, 1);
    }
    updateFilterDisplay();
    filterRows();
}

function toggleStatus(button) {
    button.classList.toggle('active');
    var input = button.parentElement.querySelector('input[type="hidden"]');
    if (button.classList.contains('active')) {
        input.value = 'on';
    } else {
        input.value = 'off';
    }
}

function toggleTooltip(fieldName) {
    var tooltip = document.getElementById(fieldName + "-tooltip");
    tooltip.classList.toggle("show");
}

function hideTooltip(fieldName) {
    var tooltip = document.getElementById(fieldName + "-tooltip");
    tooltip.classList.remove("show");
}

var acc = document.getElementsByClassName("closebtn");
var i;

for (i = 0; i < acc.length; i++) {
    acc[i].onclick = function(){
        var div = this.parentElement;
        div.style.opacity = "0";
        setTimeout(function(){ div.style.display = "none"; }, 600);
    }
}

function createMessageElement(messageText, messageTags) {
    var newDiv = document.createElement("div");
    newDiv.classList.add("alert");
    newDiv.classList.add(messageTags);
    newDiv.appendChild(document.createTextNode(messageText));
    var messageContainer = document.getElementById("message-container");
    messageContainer.appendChild(newDiv);
}

document.getElementById("activeConnector").addEventListener("change", function() {
    document.getElementById("connectorForm").submit();
});

function popUpDection(id) {
    var detection = document.getElementById(id);
    if ("hidden" in detection.attributes){
        detection.removeAttribute("hidden");
    } else {
        detection.setAttribute("hidden", "");
    }
}

function toggleDataHistoric() {
    var sourceSelect = document.getElementById("source");
    var targetSelect = document.getElementById("target");
    var selectedSource = sourceSelect.value;
    var selectedTarget = targetSelect.value;

    var divsToHide = document.querySelectorAll("[id^='history'], #Current");
    divsToHide.forEach(function(div) {
        div.style.display = "none";
    });

    if (selectedSource !== "None") {
        document.getElementById(selectedSource).style.display = "block";
    }
    if (selectedTarget !== "None") {
        document.getElementById(selectedTarget).style.display = "block";
    }
}