(function () {
  let accessibleId = 0;

  async function request(path, options) {
    const config = Object.assign({}, options || {});
    const headers = Object.assign({'Content-Type': 'application/json'}, config.headers || {});
    const token = window.sessionStorage ? window.sessionStorage.getItem('assessment_admin_token') : '';
    if (token) headers['X-Assessment-Token'] = token;
    config.headers = headers;
    const response = await fetch(path, config);
    const text = await response.text();
    let data = {};
    if (text) {
      try {
        data = JSON.parse(text);
      } catch (_) {
        data = {error: {message: '服务返回了无法解析的响应', correlation_id: response.headers.get('X-Correlation-ID') || ''}};
      }
    }
    if (!response.ok) throw data;
    return data;
  }

  function describeError(error) {
    if (error && error.error) {
      const suffix = error.error.correlation_id ? ' · ' + error.error.correlation_id : '';
      return String(error.error.message || '请求失败') + suffix;
    }
    return String(error && error.message || error || '未知错误');
  }

  function enhanceAccessibility(root) {
    const scope = root && root.querySelectorAll ? root : document;
    scope.querySelectorAll('.field label:not([for])').forEach(label => {
      if (label.querySelector('input, select, textarea, button')) return;
      const field = label.closest('.field');
      const control = field && field.querySelector('input:not([type="hidden"]), select, textarea, button');
      if (!control) return;
      if (!control.id) control.id = 'assessment-field-' + (++accessibleId);
      label.htmlFor = control.id;
    });
    scope.querySelectorAll('button.close').forEach(button => {
      if (!button.getAttribute('aria-label')) button.setAttribute('aria-label', '关闭');
      if (!button.getAttribute('title')) button.setAttribute('title', '关闭');
    });
  }

  function installAccessibility(root) {
    enhanceAccessibility(root || document);
    const observer = new MutationObserver(records => {
      records.forEach(record => record.addedNodes.forEach(node => {
        if (node.nodeType === 1) enhanceAccessibility(node);
      }));
    });
    observer.observe((root || document).documentElement || (root || document), {childList: true, subtree: true});
    return observer;
  }

  window.AssessmentRuntime = {request, describeError, enhanceAccessibility, installAccessibility};
})();
