var currentNode = null;
var templateTable;

$(document).ready(function(){
  var canvas = document.getElementById('canvas'); 
  var stage = new JTopo.Stage(canvas); // 创建一个舞台对象

  var scene = new JTopo.Scene(stage); // 创建一个场景对象
  // scene.background = '/static/images/bg.jpg';
  scene.alpha = 1;
  scene.backgroundColor = '242,242,242';  
  
  // 创建云端节点
  var local = createSingleNode({
    x: 350,
    y: 200,
    w: 40,
    h: 40,
    text: 'Cloud-GW',
    // fontColor: '170,170,170',
    img: 'frame.png',
    dragable: false
  }, scene);

  // 创建 cpe 节点
  var cpe1 = createSingleNode({
    x: 380,
    y: 225,
    w: 40,
    h: 40,
    text: 'CPE1',
    // fontColor: '170,170,170',    
    img: 'cpe.png',
    dragable: false
  }, scene);

  var cpe2 = createSingleNode({
    x: 380,
    y: 305,
    w: 40,
    h: 40,
    text: 'CPE2',
    // fontColor: '170,170,170',    
    img: 'cpe.png',
    dragable: false
  }, scene);

  var cpe3 = createSingleNode({
    x: 450,
    y: 305,
    w: 40,
    h: 40,
    text: 'CPE3',
    // fontColor: '170,170,170',        
    img: 'cpe.png',
    dragable: false
  }, scene);

  var cpe4 = createSingleNode({
    x: 450,
    y: 225,
    w: 40,
    h: 40,
    text: 'CPE4',
    // fontColor: '170,170,170',        
    img: 'cpe.png',
    dragable: false
  }, scene);

  var menuList = $('#contextmenu'),
  menuItem = menuList.find('a');
  
  menuItem.click(function() {
    if($(this)[0].id === 'check-info') {
      window.open('/health_checks?devicename=1');
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

  // getNodes(function(nodeList) {
  //   var cpeList = nodeList.map(function(cpe){
  //     return {
  //       x: Math.random() * 600,
  //       y: Math.random() * 500,
  //       w: 30,
  //       h: 30,
  //       text: cpe.switch.name,
  //       img: 'switch.png',
  //       dragable: true,
  //       nodeType: 'switch'
  //     };
  //   });
  //   var addedNodeList = createNodes(cpeList, scene);
  //   for (var i = 0, j = addedNodeList.length;i < j;i++) {
  //     createLink(addedNodeList[i], local, '', scene);
  //     nodeList[i].devices.forEach(function(device){
  //       device.x = Math.random() * 600,
  //       device.y = Math.random() * 500,
  //       device.w = 40,
  //       device.h = 40,
  //       device.text = device.ip,
  //       device.img = 'vpn.png',
  //       device.dragable = true,
  //       device.nodeType = 'terminal'
  //     });
  //     var addedDeviceList = createNodes(nodeList[i].devices, scene);
  //     for (var x = 0, y = addedDeviceList.length;x < y;x++) {
  //       createLink(addedDeviceList[x], addedNodeList[i], '', scene);
  //     }
  //   }
  // });

  getNodes(function(nodeList) {
    console.log(nodeList);
    nodeList.forEach(function(node){
      node.x = randomNodePosition('x');
      node.y = randomNodePosition('y');
      node.w = 40;
      node.h = 40;
      node.text = node.name;
      node.img = 'switch_2.png';
      node.dragable = true;
      node.nodeType = 'switch'
    })
    var addedNodeList = createNodes(nodeList, scene);
    for (var i = 0, j = addedNodeList.length;i < j;i++) {
      var linkText = '入节点PPS: ' + addedNodeList[i].input_pps + '; 出节点PPS: ' + addedNodeList[i].output_pps;
      createLink(addedNodeList[i], local, linkText, scene);
      // createLink(local, addedNodeList[i], '', scene, addedNodeList[i].input_pps);      
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
      x: randomNodePosition('x'),
      y: randomNodePosition('y'),
      w: 40,
      h: 40,
      img: 'switch_2.png',
      dragable: true,
      text: 'Node ' + i,
      // fontColor: '170,170,170'    
    }
    nodeList.push(singleNode);
  }

  return nodeList;
}

// 生成节点位置
function randomNodePosition(type) {
  var result;
  if (type === 'x') {
    result = Math.random() * 800;
    if(result >= 320 && result <= 560) {
      return randomNodePosition('x');
    }
    else {
      return result;
    }
  } else {
    result = Math.random() * 500;
    if(result >= 170 && result <= 410) {
      return randomNodePosition('y');
    }
    else {
      return result;
    }
  }
}

// 添加节点数组至拓扑
function createNodes (nodeList, scene) {
  var addedNodeList = []
  for (var i = 0, j = nodeList.length;i < j;i++) {
    var node = nodeList[i];
    var addedNode = createSingleNode(node, scene);
    addedNode.ip = node.ip;
    addedNode.input_pps = node.input_pps;
    addedNode.output_pps = node.output_pps;    
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
  node.fontColor = nodeInfo.fontColor || '0,0,0';
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
function createLink (fromNode, toNode, text, scene, level) {
  var link = new JTopo.Link(fromNode, toNode, text);
  // var path = link.getPath();
  // console.log(path);
  // var pathLength = Math.floor(Math.sqrt(Math.pow(path[0].x - path[1].x,2) + Math.pow(path[0].y - path[1].y, 2)));
  // console.log(pathLength);
  link.arrowsRadius = 10;
  link.lineWidth = level ? level * 3 : 3;
  link.offsetGap = 90;
  // link.dashedPattern = dashedPattern;
  link.bundleOffset = 40; // 折线拐角处的长度
  link.bundleGap = 20; // 线条之间的间隔
  // link.arrowsOffset = -10;  
  link.textOffsetY = 30; // 文本偏移量（向下3个像素）
  link.fontColor = '81,181,220'; // 文本偏移量（向下3个像素）  
  link.strokeColor = '81,181,220';    
  console.log(link);
  // setInterval(function(){
  //   link.arrowsOffset++;
  //   if (link.arrowsOffset === 0) {
  //     link.arrowsOffset = -10;
  //   }
  // }, 100);
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
  // console.log(node);
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
  // var mockData = [{
  //   switch: {
  //     name: 'CPE1',
  //     id: 1
  //   },
  //   devices: [{ip: '10.0.0.0'}, {ip: '10.0.0.1'}, {ip: '10.0.0.2'}]
  // }, {
  //   switch: {
  //     name: 'CPE2',
  //     id: 2
  //   },
  //   devices: [{ip: '192.0.0.0'}, {ip: '192.0.0.1'}, {ip: '192.0.0.2'}]
  // }];
  // callback(mockData);
  $.ajax({
    type: "get",
    url: "/traffic_path_nodes",
    success: function (response) {
      if (response.errmsg === 'success') {
        callback(JSON.parse(response.data));
      }
    }
  });
}
