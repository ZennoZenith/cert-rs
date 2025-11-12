class WebComponent extends HTMLElement {
  private template: HTMLTemplateElement;
  private templateContent: DocumentFragment;

  constructor(templateId: string) {
    super();
    const maybeTemplate = document.getElementById(
      templateId,
    ) as HTMLTemplateElement | null;

    if (!maybeTemplate) {
      throw new Error(`template element with id=${templateId} not found`);
    }

    this.template = maybeTemplate;

    const templateContent = this.template.content.cloneNode(
      true,
    ) as DocumentFragment;

    this.templateContent = templateContent;
  }

  connectedCallback() {
    this.appendChild(this.templateContent);
  }
}

function webComponentGenerator(
  templateId: string,
  _constructor?: CustomElementConstructor,
) {
  if (_constructor) {
    customElements.define(templateId, _constructor);
    return;
  }

  class Intermediate extends WebComponent {
    constructor() {
      super(templateId);
    }
  }
  customElements.define(templateId, Intermediate);
}

export class WebComponentRegistery {
  private static webComponents: Set<string> = new Set();

  private constructor() {
    throw new Error("Cannot instantiate static class WebComponentRegistery");
  }

  public static register(
    webComponentName: string,
    _constructor?: CustomElementConstructor,
  ) {
    if (WebComponentRegistery.webComponents.has(webComponentName)) {
      return;
    }

    if (customElements.get(webComponentName)) {
      WebComponentRegistery.webComponents.add(webComponentName);
      return;
    }

    webComponentGenerator(webComponentName, _constructor);
    WebComponentRegistery.webComponents.add(webComponentName);
  }
}
