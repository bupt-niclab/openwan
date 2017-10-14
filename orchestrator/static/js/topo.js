$(document).ready(function(){
  var canvas = document.getElementById('canvas'); 
  var stage = new JTopo.Stage(canvas); // 创建一个舞台对象

  var scene = new JTopo.Scene(stage); // 创建一个场景对象
  scene.background = '/static/images/bg.jpg';

  var currentNode = null;
  
  // 创建公网节点
  var local = createSingleNode({
    x: 500,
    y: 250,
    w: 40,
    h: 40,
    text: 'Cloud-GW',
    img: 'cloud.png',
    dragable: false
  }, scene);

  // makeNodeEditable(scene);

  var menuList = $('#contextmenu'),
  menuItem = menuList.find('a');
  
  var templateTable;
  menuItem.click(function() {
    if($(this)[0].id === 'config-template') {
      $('#config-template-modal').modal();
        // TODO: 渲染表格
      if(!templateTable) {
        tamplateTable = $('#templates').DataTable({
          ajax: {
            url: '/api_templates'
          },
          pageLength: 5,
          columns: [{
            data: "tid"
          }, {
            data: "name"
          }],
          columnDefs: [
          {
            render: function(data, type, row, meta) {
              // return '<a href="' + data + '" target="_blank">' + row.title + '</a>';
              return '<button class="btn btn-primary" onclick="applyTemplate">操作</button>';              
            },
            //指定是第三列
            targets: 2
          }]
        });
        // templateTable.on('order.dt search.dt', function() {
        //     t.column(0, {
        //       "search": 'applied',
        //       "order": 'applied'
        //     }).nodes().each(function(cell, i) {
        //       cell.innerHTML = i + 1;
        //   });
        // }).draw();
      }
    } else {
      alert('查看成功');
    }
    menuList.hide();
  });

  stage.click(function(event) {
    if (event.button === 0) {
      menuList.hide();
    }
  });

  // var applyBtn = $('.apply-template');
  // var appliedTemplate = 0; // TODO:读取数据并解析该节点是否有应用模板
  // applyBtn.click(function(e){
  //   // console.log($(this)[0]);
  //   var thisBtn = $($(this)[0]);
  //   // console.log(thisBtn);
  //   if (appliedTemplate === 1) {      
  //     // TODO:找到已被应用的模板，取消其按钮样式
   
  //   } else {
  //     appliedTemplate = 1;
  //   }
  //   thisBtn.text('已应用');
  //   thisBtn.attr('disabled', 'disabled'); 
  //   // thisBtn.innerText = '已应用';
  //   // console.log(thisBtn.dataset.templateType);
  // });

  getNodes(function(nodeList) {
    var cpeList = nodeList.map(function(cpe){
      return {
        x: Math.random() * 600,
        y: Math.random() * 500,
        w: 30,
        h: 30,
        text: cpe.switch.name,
        img: 'switch.png',
        dragable: true,
        nodeType: 'switch'
      };
    });
    var addedNodeList = createNodes(cpeList, scene);
    for (var i = 0, j = addedNodeList.length;i < j;i++) {
      createLink(addedNodeList[i], local, '', scene);
      nodeList[i].devices.forEach(function(device){
        device.x = Math.random() * 600,
        device.y = Math.random() * 500,
        device.w = 40,
        device.h = 40,
        device.text = device.ip,
        device.img = 'vpn.png',
        device.dragable = true,
        device.nodeType = 'terminal'
      });
      var addedDeviceList = createNodes(nodeList[i].devices, scene);
      for (var x = 0, y = addedDeviceList.length;x < y;x++) {
        createLink(addedDeviceList[x], addedNodeList[i], '', scene);
      }
    }
  });
  // var nodeList = simulateNodes();
  // var addedNodeList = createNodes(nodeList, scene);
  // for (var i = 0, j = addedNodeList.length;i < j;i++) {
  //   createLink(addedNodeList[i], local, '', scene);
  // }

});

// 模拟生成节点
function simulateNodes () {
  var nodeList = [];

  for (var i = 0;i < 5; i++) {
    var singleNode = {
      x: Math.random() * 800,
      y: Math.random() * 500,
      w: 40,
      h: 40,
      img: 'vpn.png',
      dragable: true,
      text: 'Node ' + i
    }
    nodeList.push(singleNode);
  }

  return nodeList;
}

// 添加节点数组至拓扑
function createNodes (nodeList, scene) {
  var addedNodeList = []
  for (var i = 0, j = nodeList.length;i < j;i++) {
    var node = nodeList[i];
    var addedNode = createSingleNode(node, scene);
    addedNodeList.push(addedNode);
  }
  return addedNodeList;
}

// 添加单个节点至拓扑
function createSingleNode (nodeInfo, scene) {
  var node = new JTopo.Node(nodeInfo.text);
  node.setLocation(nodeInfo.x, nodeInfo.y);
  node.setSize(nodeInfo.w, nodeInfo.h);
  if (nodeInfo.img) {
    node.setImage('/static/images/' + nodeInfo.img, true);
  }
  node.dragable = nodeInfo.dragable;
  if(nodeInfo.state === 'UP') {
    node.alarm = 'up';
    node.alarmColor = '0, 255, 0';
  } else if (nodeInfo.state === 'DOWN') {
    node.alarm = 'down';
  }
  scene.add(node);
  // TODO: 判断是否是 CPE 节点
  if (nodeInfo.nodeType === 'switch') {
    node.addEventListener('mouseup', function(event) {
      handler(event, node);
    })
  }
  return node;
}

// 创建节点间连线
function createLink (fromNode, toNode, text, scene) {
  var link = new JTopo.Link(fromNode, toNode, text);
  link.lineWidth = 3;
  // link.dashedPattern = dashedPattern;
  link.bundleOffset = 60; // 折线拐角处的长度
  link.bundleGap = 20; // 线条之间的间隔
  link.textOffsetY = 3; // 文本偏移量（向下3个像素）
  link.strokeColor = '255,255,255';
  scene.add(link);
  return link;
}

// 创建动态连线
function makeNodeEditable (scene) { 
  var beginNode = null;

  var tempNodeA = new JTopo.Node('tempA');;
  tempNodeA.setSize(1, 1);
  
  var tempNodeZ = new JTopo.Node('tempZ');;
  tempNodeZ.setSize(1, 1);
  
  var link = new JTopo.Link(tempNodeA, tempNodeZ);
  
  scene.mouseup(function(e) {
    if (e.button === 2) {
      scene.remove(link);
      return;
    }
    if (e.target !== null && e.target instanceof JTopo.Node) {
      if (beginNode === null) {
        beginNode = e.target;
        scene.add(link);
        tempNodeA.setLocation(e.x, e.y);
        tempNodeZ.setLocation(e.x, e.y);
      } else if (beginNode !== e.target) {
        var endNode = e.target;
        var l = new JTopo.Link(beginNode, endNode);
        scene.add(l);
        l.addEventListener('mouseup', function(event) {
          handler(event);
        });
        beginNode = null;
        scene.remove(link);
      } else {
        beginNode = null;
      }
    } else {
      scene.remove(link);
    }
  });
  
  scene.mousedown(function(e){
    if(e.target == null || e.target === beginNode || e.target === link){
      scene.remove(link);
    }
  });

  scene.mousemove(function(e){
    tempNodeZ.setLocation(e.x, e.y);
  });
}

// 右键弹出菜单
function handler (event, node) {
  currentNode = node;
  if (event.button === 2) {
    // console.log(event);
    $('#contextmenu').css({
      top: event.layerY,
      left: event.layerX + 40
    }).show();
  }
}

// 获取节点信息
function getNodes(callback) {
  var mockData = [{
    switch: {
      name: 'CPE1',
      id: 1
    },
    devices: [{ip: '10.0.0.0'}, {ip: '10.0.0.1'}, {ip: '10.0.0.2'}]
  }, {
    switch: {
      name: 'CPE2',
      id: 2
    },
    devices: [{ip: '192.0.0.0'}, {ip: '192.0.0.1'}, {ip: '192.0.0.2'}]
  }];
  callback(mockData);
  // $.ajax({
  //   type: "get",
  //   url: "/traffic_path_nodes",
  //   success: function (response) {
  //     if (response.err_msg === 'success') {
  //       callback(response.data);
  //     }
  //   }
  // });
}

// 获取模板列表
function getTemplates(callback) {
  $.ajax({
    type: 'get',
    url: '/api_templates',
    success: function(response) {
      if (response.err_msg === 'success') {
        callback(response.data);
      }
    }
  })
}


function applyTemplate() {
  
}
