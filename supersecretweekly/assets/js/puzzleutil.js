function checkURL(url) {
    var http = new XMLHttpRequest();
    http.open('HEAD', url, false);
    http.send();
    if (http.status == 200)
        return true;
    else
        return false;
}

function updateText(responseText, answer="", answerURL=""){
    textResponse = document.getElementById("responsetext")
    response = responseText.split("\n")[0].trim()
    switch(response){
    case "correct!!":
        window.location = answerURL.slice(0, -5) + "/success.html";
        break;
    case "correct!":
        textResponse.outerHTML = `<h5 id="responsetext" style="color:green">correct! ${answer} is the correct answer :)</h5>`;
        puzzleID = getPuzzleId();
        keyFrag = responseText.split("\n")[1]
        setPuzzleAnswer(puzzleID, answer, keyFrag)
        break;
    case "incorrect!":
        textResponse.outerHTML = `<h5 id="responsetext" style="color:red">sorry, ${answer} is not the correct answer :(</h5>`;
        break;
    default:
        textResponse.outerHTML = `<h5 id="responsetext" style="color:yellow">${response} (${answer})</h5>`;
    }
}

async function submitAnswer(){
    textResponse = document.getElementById("responsetext")
    textResponse.outerHTML = '<h5 id="responsetext"></h5>'
    answerBox = document.getElementById("answerbox")
    submitBox = document.getElementById("submitbox")
    answer = answerBox.value.replace(/[^a-zA-Z]/gi, '').toUpperCase();
    rawanswer = answer;
    submitBox.innerHTML = "Submitting..."
    for (i=0;i<50000;i++){
        answer = await sha256(answer)
    }
    answerURL = window.location.href + answer + ".html";
    submitBox.innerHTML = "Check Answer"
    if (checkURL(answerURL)){
        fetch(answerURL)
        .then(response => response.text())
        .then(text => updateText(text, rawanswer, answerURL))
    }
    else {
        updateText("incorrect!", rawanswer)
    }
}
  
async function sha256(message) {
    const msgBuffer = new TextEncoder().encode(message);                    
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    return hashHex;
}

function copyToClipboard(textIndex) {
    toCopy = texts[textIndex];
    navigator.clipboard.writeText(toCopy);
}

function loadPuzzleToken(){
    try {
        puzzleToken = window.localStorage.getItem("puzzleToken")
        if (puzzleToken == undefined){
            return {}
        }
        token = JSON.parse(puzzleToken)
        return token
    } catch {
        return {}
    }
}

function getPuzzleId(){
    try {
        return document.getElementById("puzzleId").innerHTML
    } catch {
        return 0
    }
}

function setPuzzleAnswer(puzzleID, answer, keyFrag){
    token = loadPuzzleToken();
    token[puzzleID] = [answer, keyFrag];
    setPuzzleToken(token);
}

function setPuzzleToken(puzzleToken){
    token = JSON.stringify(puzzleToken);
    window.localStorage.setItem("puzzleToken", token)
}

function checkSubmitted(){
    puzzleID = getPuzzleId();
    token = loadPuzzleToken();
    if (token[puzzleID] != undefined && puzzleID != 0){
        editPuzzleAnswer(token[puzzleID][0])
    }
}

function editPuzzleAnswer(answer){
    textResponse = document.getElementById("responsetext")
    textResponse.outerHTML = `<h5 id="responsetext" style="color:green">correct! ${answer} is the correct answer :)</h5>`;
}

function initialize(){
    checkSubmitted();
}