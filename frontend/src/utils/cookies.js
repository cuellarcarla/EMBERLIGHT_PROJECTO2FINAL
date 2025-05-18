export function getCookie(name) {
  return document.cookie.match(/csrftoken=([^;]+)/)?.[1];
}
  
export function setCookie(name, value, days) {
  const date = new Date();
  date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
  document.cookie = `${name}=${value};expires=${date.toUTCString()};path=/`;
}