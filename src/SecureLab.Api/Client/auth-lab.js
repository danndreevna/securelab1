const registerResult = document.querySelector("#registerResult");
const authResult = document.querySelector("#authResult");
const profile = document.querySelector("#profile");
const createResult = document.querySelector("#createResult");

document.querySelector("#register").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const response = await fetch("/api/auth/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.fromEntries(new FormData(form)))
    });
    form.elements.password.value = "";
    registerResult.textContent = `Register: ${response.status}`;
    if (response.ok) {
        registerResult.textContent += " - now sign in using the form below.";
    }
});

document.querySelector("#login").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const response = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(Object.fromEntries(new FormData(form)))
    });
    form.elements.password.value = "";
    authResult.textContent = `Login: ${response.status}`;
    await refreshProfile();
});

document.querySelector("#me").addEventListener("click", refreshProfile);

async function refreshProfile() {
    const response = await fetch("/api/me");
    if (response.ok) {
        const data = await response.json();
        profile.textContent = `Signed in: ${data.userName} (${data.displayName})`;
    } else {
        profile.textContent = "Not signed in";
    }
}

document.querySelector("#logout").addEventListener("click", async () => {
    const response = await fetch("/api/auth/logout", { method: "POST" });
    authResult.textContent = `Logout: ${response.status}`;
    createResult.textContent = "";
    await refreshProfile();
});

document.querySelector("#create").addEventListener("submit", async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const fields = Object.fromEntries(new FormData(form));
    const payload = {
        title: fields.title,
        description: fields.description,
        severity: fields.severity,
        occurredAtUtc: new Date(fields.occurredAtUtc).toISOString()
    };
    const response = await fetch("/api/incidents", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload)
    });
    const body = await response.text();
    createResult.textContent = `Create: ${response.status}\n${body}`;
});