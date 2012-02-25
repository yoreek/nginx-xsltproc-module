var pattOpened   = new RegExp("\\bclosed\\b");
var pattNodeText = new RegExp("\\bnode-text\\b");

window.onload = function(){
	document.getElementById("profiler").onclick = function(e){
		e = e || window.event;

		var src = e.target || e.srcElement;
		if (!src) return false;

		if (src.tagName != 'LABEL') src = src.parentNode;
		if (src.tagName != 'LABEL') src = src.parentNode;
		if (src.tagName != 'LABEL') return false;

		src = src.parentNode;

		if ( pattNodeText.test(src.className) ) return false;

		if ( pattOpened.test(src.className) ) {
			src.className = src.className.replace(pattOpened, '');
		}
		else {
			src.className += ' closed';
		}

		return false;
	};
}
