function analyzeFile() {
    const apiKey = 'YOUR_API_KEY'; // Reemplaza con tu clave de API de VirusTotal

    const fileInput = document.getElementById('fileInput');
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = 'Analizando archivo...';

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    fetch('https://www.virustotal.com/api/v3/files', {
        method: 'POST',
        headers: {
            'x-apikey': apiKey,
        },
        body: formData
    })
        .then(response => response.json())
        .then(data => {
            console.log(data);
            checkAnalysisStatus(data.data.id, 1);
        })
        .catch(error => {
            resultDiv.innerHTML = 'Error al analizar el archivo: ' + error.message;
        });
}

function scanUrl() {
    const apiKey = 'YOUR_API_KEY'; // Reemplaza con tu clave de API de VirusTotal
    const urlInput = document.getElementById('urlInput');
    const resultDiv = document.getElementById('result');
    const urlToScan = urlInput.value;

    resultDiv.innerHTML = 'Escaneando URL...';

    fetch('https://www.virustotal.com/api/v3/urls', {
        method: 'POST',
        headers: {
            'x-apikey': apiKey,
            'content-type': 'application/x-www-form-urlencoded'
        },
        body: new URLSearchParams({ url: urlToScan })
    })
        .then(response => response.json())
        .then(data => {
            console.log(data);
            checkAnalysisStatus(data.data.id, 2);
        })
        .catch(error => {
            resultDiv.innerHTML = 'Error al escanear la URL: ' + error.message;
        });
}

function checkAnalysisStatus(analysisId, typeScan) {
    const apiKey = 'YOUR_API_KEY'; // Reemplaza con tu clave de API de VirusTotal
    const resultDiv = document.getElementById('result');
    resultDiv.innerHTML = 'Comprobando el estado del análisis...';

    fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        method: 'GET',
        headers: {
            'x-apikey': apiKey
        }
    })
        .then(response => response.json())
        .then(data => {
            // Comprobar el estado del análisis
            if (data.data.attributes.status === 'completed') {
                console.log(data);
                // Verifica que los datos estén disponibles
                let responseData = data;
                if (responseData.data.attributes) {
                    const attributes = responseData.data.attributes;

                    // Crear una tabla HTML
                    const table = document.createElement('table');
                    table.className = 'table'; // Clase CSS opcional para estilo
                    table.className = 'table table-striped'; // Clases de Bootstrap para tablas

                    // Encabezados de la tabla
                    const headerRow = table.insertRow(0);
                    const headers = ['Motor de análisis', 'Categoría', 'Resultado', 'Método'];
                    headers.forEach(headerText => {
                        const header = document.createElement('th');
                        header.innerHTML = headerText;
                        headerRow.appendChild(header);
                    });

                    // Filas de datos
                    for (const engineName in attributes.results) {
                        const result = attributes.results[engineName];
                        const row = table.insertRow(-1);
                        const data = [engineName, result.category, result.result, result.method];
                        data.forEach(text => {
                            const cell = row.insertCell();
                            cell.innerHTML = text;
                        });
                    }

                    // Agregar la tabla al div
                    resultDiv.innerHTML = ''; // Limpia cualquier contenido anterior
                    resultDiv.appendChild(table);

                    const divExt = document.createElement('div');
                    resultDiv.appendChild(divExt);

                    /**
                     * Aqui se pinta la info extra del archivo o de la url
                     */
                    const tableExt = document.createElement('table');
                    tableExt.classList.add('table', 'table-striped');

                    const tbody = document.createElement('tbody');

                    // Encabezados de la tabla
                    const row = document.createElement('tr');
                    const cellKey = document.createElement('td');
                    const cellValue = document.createElement('td');
                    cellKey.textContent = "Tipo resumen criptográfico";
                    cellValue.textContent = "Valor";
                    row.appendChild(cellKey);
                    row.appendChild(cellValue);
                    tbody.appendChild(row);

                    if (typeScan == 1) {
                        for (const key in responseData.meta.file_info) {
                            const row = document.createElement('tr');
                            const cellKey = document.createElement('td');
                            const cellValue = document.createElement('td');
                            cellKey.textContent = key;
                            cellValue.textContent = responseData.meta.file_info[key];
                            row.appendChild(cellKey);
                            row.appendChild(cellValue);
                            tbody.appendChild(row);
                        }

                        tableExt.appendChild(tbody);
                    }
                    else if (typeScan == 2) {
                        for (const key in responseData.meta.url_info) {
                            const row = document.createElement('tr');
                            const cellKey = document.createElement('td');
                            const cellValue = document.createElement('td');
                            cellKey.textContent = key;
                            cellValue.textContent = responseData.meta.url_info[key];
                            row.appendChild(cellKey);
                            row.appendChild(cellValue);
                            tbody.appendChild(row);
                        }

                        tableExt.appendChild(tbody);
                    }
                    resultDiv.appendChild(tableExt);
                } else {
                    resultDiv.innerHTML = 'No se encontraron datos relevantes en la respuesta.';
                }
            } else if (data.data.attributes.status === 'queued' || data.data.attributes.status === 'in_progress') {
                // El análisis está en cola o en progreso, sigue comprobando el estado
                setTimeout(() => checkAnalysisStatus(analysisId), 5000); // Comprobar cada 5 segundos
            } else {
                // Otro estado, muestra un mensaje apropiado
                resultDiv.innerHTML = 'Estado de análisis desconocido: ' + data.data.attributes.status;
            }
        })
        .catch(error => {
            resultDiv.innerHTML = 'Error al comprobar el estado del análisis: ' + error.message;
            console.error(error);
        });
}

