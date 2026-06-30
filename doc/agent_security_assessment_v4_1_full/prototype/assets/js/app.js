(function(){
  function showBootError(message, error){
    var boot = document.getElementById('boot-status');
    if (!boot) return;
    boot.className = 'boot';
    boot.innerHTML = '<strong>页面启动失败</strong><div>'+ message +'</div><pre>' + (error && (error.stack || error.message || String(error)) || '') + '</pre>';
  }
  window.addEventListener('error', function(e){ showBootError('检测到 JavaScript 运行错误，页面已停止静默空白。', e.error || e.message); });
  window.addEventListener('unhandledrejection', function(e){ showBootError('检测到未处理的 Promise 异常。', e.reason); });
  window.AssessmentPrototype = {
    boot: function(config){
      try{
        if (!window.Vue || !window.Vue.createApp) throw new Error('Vue 未加载。请检查 assets/vendor/vue.global.prod.js 是否存在。');
        var app = Vue.createApp({
          data:function(){return {
            pageId: config.pageId, pageTitle: config.pageTitle, route: config.route,
            drawer:false, modal:false, modalTitle:'操作确认', modalText:'该动作在正式产品中会调用对应 API，并写入 audit_event。', toast:'', activeTab:'overview',
            filters:{q:'', severity:'all', status:'all'},
            checklist:{a:true,b:true,c:false,d:true},
            selected:'demo',
            now:new Date().toLocaleString()
          }},
          methods:{
            openModal:function(title,text){this.modalTitle=title||'操作确认'; this.modalText=text||this.modalText; this.modal=true},
            openDrawer:function(){this.drawer=true},
            notify:function(text){var self=this; this.toast=text||'已触发原型动作'; clearTimeout(this._timer); this._timer=setTimeout(function(){self.toast=''},2200)},
            setTab:function(name){this.activeTab=name},
            mockRun:function(){this.notify('已模拟创建任务：task_demo_20260629_001')},
            mockSave:function(){this.notify('已模拟保存配置，正式实现需调用 PUT API')}
          },
          mounted:function(){
            var boot=document.getElementById('boot-status');
            if(boot) boot.remove();
          }
        });
        app.mount('#app');
      }catch(err){ showBootError('Vue 挂载失败。', err); }
    }
  };
})();
