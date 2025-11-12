import { WebComponentRegistery } from "$lib/components.js";
import { defaultSetup } from "$utils/defaultSetup.js";
import { passwordSetup } from "$utils/password.js";

class LoginForm extends HTMLElement {
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
      const { email, password } = Object.fromEntries(formData.entries());
      // console.log(Object.fromEntries(formData.entries()));

      const res = await fetch("/api/login", {
        method: "POST",
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          email,
          password,
        }),
      });
      // console.log(res);
      const json = await res.json();
      // console.log(json);

      if (json?.result?.success === true) {
        console.log("Login success");
      }

      if (json?.error?.message === "LOGIN_FAIL") {
        console.log("Login fail");
      }
    };
  }
}

function setup() {
  defaultSetup();
  passwordSetup();
  WebComponentRegistery.register("login-form", LoginForm);
}

setup();
