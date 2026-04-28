function compareVersions(v1, v2) {
    var a = v1.split('.');
    var b = v2.split('.');
    for (var i = 0; i < Math.max(a.length, b.length); i++) {
        var num1 = parseInt(a[i] || '0', 10);
        var num2 = parseInt(b[i] || '0', 10);
        if (num1 > num2) return true;
        if (num1 < num2) return false;
    }
    return true;
}

function updateData() {
    if (external.invoke("refresh")) {
        window.alert("Erro ao atualizar os dados.");
    }

    document.querySelectorAll('.date-time')[0].textContent = data.now;
    document.querySelectorAll('.date-time')[1].textContent = data.date;
    document.querySelector('#manufacturer .data').textContent = data.manufacturer;
    document.querySelector('#os .data').textContent = data.os;
    document.querySelector('#user .data').textContent = data.user;
    document.querySelector('#hostname .data').textContent = data.hostname;
    document.querySelector('#cpu .data').textContent = data.cpu;
    document.querySelector('#cpu_usage .data').textContent = data.cpu_usage;

    let mem = JSON.parse(data.memory);
    document.querySelector('#ram .data').textContent =  mem[0];
    document.querySelector('#ram_free .data').textContent =  mem[1];

    document.querySelector('#uptime .data').textContent = data.uptime;

    document.querySelector('#join').innerHTML = data.join;
    document.querySelector('#proxy').innerHTML = data.proxy;

    document.querySelector('#firewall .data').textContent = data.firewall;
    if (data.firewall !== "Ativado") {
        document.querySelector('#firewall .label').style.color = "#00b86b";
    }

    document.querySelector('#forti .data').textContent = data.forticlient;

    if ((data.forticlient !== "Não Instalado") && compareVersions(data.forticlient, "7.2.10")) {
        document.querySelector('#forti .label').style.color = "#00b86b";
    }

    document.querySelector('#crowdstrike .data').textContent = data.crowd;
    if (data.crowd !== "Não Instalado") {
        document.querySelector('#crowdstrike .label').style.color = "#00b86b";
    }

    document.querySelector('#kace .data').textContent = data.kace;
    if (data.kace !== "Não Instalado") {
        document.querySelector('#kace .label').style.color = "#00b86b";
    }
    
    document.querySelector('#netskope .data').textContent = data.netskope;
    if (data.netskope !== "Não Instalado") {
        document.querySelector('#netskope .label').style.color = "#00b86b";
    }

    document.querySelector('#ping').innerHTML = data.ping;
    if (data.ping === "ACESSO A REDE INTERNA") {
        document.querySelector('#ping').style.color = "#00b86b";
    }

    document.querySelector('#telemetria').innerHTML = data.telemetria;
    if (data.telemetria === "✅") {
        document.querySelector('#telemetria').style.color = "#00b86b";
    }

    document.querySelector('#lumu .data').textContent = data.lumu;
    if (data.lumu !== "Não Instalado") {
        document.querySelector('#lumu .label').style.color = "#00b86b";
    }

    document.querySelector('#windows_app .data').textContent = data["Windows App"];
    if (data["Windows App"] !== "Não Instalado") {
        document.querySelector('#windows_app .label').style.color = "#00b86b";
    }
    
};

external.invoke("refresh");
updateData();
setInterval(updateData, 900);

document.addEventListener('keydown', function(event) {
    event.preventDefault();
});