import { apiFetch } from "./api-fetch.js";

const stateEl = document.querySelector("#state");
const profileEl = document.querySelector("#profile");
const resultEl = document.querySelector("#result");
const registerForm = document.querySelector("#register");
const loginForm = document.querySelector("#login");
const incidentForm = document.querySelector("#incident");

function postJson(path, payload) {
  return apiFetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
}

function isJson(response) {
  return (response.headers.get("Content-Type") ?? "").includes("json");
}

async function refreshSessionState() {
  const response = await apiFetch("/api/auth/session-check");
  if (response.status === 204) {
    stateEl.textContent = "Сеанс активний";
  } else if (response.status === 401) {
    stateEl.textContent = "Не ввійшли";
    profileEl.textContent = "";
  } else {
    stateEl.textContent = "Стан невідомий";
  }
}

async function loadProfile() {
  const response = await apiFetch("/api/me");
  if (response.status === 401) {
    profileEl.textContent = "";
    resultEl.textContent = "GET /api/me: 401";
    return;
  }
  if (!response.ok || !isJson(response)) {
    profileEl.textContent = "";
    resultEl.textContent = `GET /api/me: ${response.status}`;
    return;
  }
  const profile = await response.json();
  profileEl.textContent = `Користувач: ${profile.userName}; роль: ${profile.role}`;
  resultEl.textContent = "GET /api/me: 200";
}

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(registerForm));
  const response = await postJson("/api/auth/register", {
    userName: data.userName,
    email: data.email,
    displayName: data.displayName,
    password: data.password,
  });
  registerForm.elements.password.value = "";
  resultEl.textContent = response.status === 201
    ? "Реєстрація: 201. Тепер увійдіть."
    : `Реєстрація: ${response.status}`;
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(loginForm));
  const response = await postJson("/api/auth/login", {
    userName: data.userName,
    password: data.password,
  });
  loginForm.elements.password.value = "";
  resultEl.textContent = `Login: ${response.status}`;
  if (response.status === 204) {
    await refreshSessionState();
    await loadProfile();
  } else {
    await refreshSessionState();
  }
});

incidentForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(incidentForm));
  const response = await postJson("/api/incidents", {
    title: data.title,
    description: data.description,
    severity: data.severity,
    occurredAtUtc: new Date(data.occurredAt).toISOString(),
  });
  if (response.status === 201 && isJson(response)) {
    const created = await response.json();
    resultEl.textContent = `Створено: 201, id ${created.id}`;
  } else if (response.status === 400 && isJson(response)) {
    const problem = await response.json();
    resultEl.textContent = `400, поля з помилками: ${Object.keys(problem.errors ?? {}).join(", ")}`;
  } else {
    resultEl.textContent = `Створення: ${response.status}`;
  }
});

document.querySelector("#logout").addEventListener("click", async () => {
  const response = await apiFetch("/api/auth/logout", { method: "POST" });
  profileEl.textContent = "";
  incidentForm.reset();
  resultEl.textContent = `Logout: ${response.status}`;
  await refreshSessionState();
});

document.querySelector("#check-me").addEventListener("click", loadProfile);

refreshSessionState().catch(() => {
  stateEl.textContent = "Стан невідомий";
});