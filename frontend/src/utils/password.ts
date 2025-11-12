import { WebComponentRegistery } from "$lib/components.js";

export class CustomPassword extends HTMLElement {
  static observedAttributes = ["showpassword"];

  connectedCallback() {
    const element = this.querySelector<HTMLInputElement>(
      "input[type='password']",
    );

    if (!element) {
      console.warn("Input password not found when registering CustomPassword");
      return;
    }

    const showpassword = this.attributes.getNamedItem("showpassword");
    if (showpassword !== null) {
      this.enableShowPassword(element);
    }
  }

  private enableShowPassword(inputElement: HTMLInputElement) {
    inputElement.addEventListener("keydown", (event) => {
      if (event.ctrlKey) {
        window.dispatchEvent(
          new CustomEvent("showpassword", {
            detail: {
              value: "true",
            },
          }),
        );
        inputElement.type = "text";
      }
    });

    inputElement.addEventListener("keyup", () => {
      window.dispatchEvent(
        new CustomEvent("showpassword", {
          detail: {
            value: "false",
          },
        }),
      );
      inputElement.type = "password";
    });
  }

  // attributeChangedCallback(name: string, oldValue: unknown, newValue: unknown) {
  //   console.log(
  //     `Attribute ${name} has changed from ${oldValue} to ${newValue}.`,
  //   );
  // }
}

export function passwordSetup() {
  WebComponentRegistery.register("custom-password", CustomPassword);
}
