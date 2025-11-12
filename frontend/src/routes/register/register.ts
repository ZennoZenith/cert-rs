import { WebComponentRegistery } from "$lib/components.js";
import { defaultSetup } from "$utils/defaultSetup.js";
import { passwordSetup } from "$utils/password.js";

const form = document.getElementById("form");
const firstname_input = document.getElementById(
  "firstname-input",
) as HTMLInputElement;
const email_input = document.getElementById("email-input") as HTMLInputElement;
const password_input = document.getElementById(
  "password-input",
) as HTMLInputElement;
const error_message = document.getElementById(
  "error-message",
) as HTMLParagraphElement;

form?.addEventListener("submit", (e) => {
  let errors = [];

  if (firstname_input) {
    // If we have a firstname input then we are in the signup
    errors = getSignupFormErrors(
      firstname_input.value,
      email_input.value,
      password_input.value,
    );
  } else {
    // If we don't have a firstname input then we are in the login
    errors = getLoginFormErrors(email_input.value, password_input.value);
  }

  if (errors.length > 0) {
    // If there are any errors
    e.preventDefault();
    error_message.innerText = errors.join(". ");
  }
});

function getSignupFormErrors(
  firstname: string,
  email: string,
  password: string,
) {
  const errors = [];

  if (firstname === "" || firstname == null) {
    errors.push("Firstname is required");
    firstname_input.parentElement?.classList.add("incorrect");
  }
  if (email === "" || email == null) {
    errors.push("Email is required");
    email_input.parentElement?.classList.add("incorrect");
  }
  if (password === "" || password == null) {
    errors.push("Password is required");
    password_input.parentElement?.classList.add("incorrect");
  }
  if (password.length < 8) {
    errors.push("Password must have at least 8 characters");
    password_input.parentElement?.classList.add("incorrect");
  }
  return errors;
}

function getLoginFormErrors(email: string, password: string) {
  const errors = [];

  if (email === "" || email == null) {
    errors.push("Email is required");
    email_input.parentElement?.classList.add("incorrect");
  }
  if (password === "" || password == null) {
    errors.push("Password is required");
    password_input.parentElement?.classList.add("incorrect");
  }

  return errors;
}

const allInputs = [firstname_input, email_input, password_input].filter(
  (input) => input != null,
);

allInputs.forEach((input) => {
  input.addEventListener("input", () => {
    if (input.parentElement?.classList.contains("incorrect")) {
      input.parentElement.classList.remove("incorrect");
      error_message.innerText = "";
    }
  });
});

class RegisterForm extends HTMLElement {
  connectedCallback() {
    this.onsubmit = async (event) => {
      event.preventDefault();

      const target = (
        event as SubmitEvent & { target: EventTarget & HTMLFormElement }
      ).target;

      if (!target) {
        return;
      }

      const formData = new FormData(target);
      const { name, email, password, toc, subemail } = Object.fromEntries(
        formData.entries(),
      );
      console.log(Object.fromEntries(formData.entries()));

      if (toc !== "on") {
        alert("Accept Term and condition");
        return;
      }

      const res = await fetch("/api/register", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          name,
          email,
          password,
          toc: toc === "on",
          subscribeEmail: subemail === "on",
        }),
      });
      // console.log(res);
      const json = await res.json();
      // console.log(json);

      if (json?.result?.success === true) {
        console.log("Registered successfully");
      }

      if (json?.error?.message === "USER_ALREADY_EXISTS") {
        console.log("Registeration fail");
      }
    };
  }
}

function setup() {
  defaultSetup();
  passwordSetup();
  WebComponentRegistery.register("register-form", RegisterForm);
}

setup();
